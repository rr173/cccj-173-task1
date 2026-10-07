# 企业邮件端到端加密策略网关

在邮件出站链路上提供 **策略判定 + 密钥快照冻结 + fail-closed 投递 + 可验证投递清单**
的网关。加密全部基于 `cryptography` 库的真实原语（Ed25519 / X25519 / AES-256-GCM / HKDF），
不是模拟。

## 威胁模型与核心不变量

1. **发送前按收件人域、身份、时间点解析证书**：证书按版本留存（轮换不覆盖、
   撤销只追加），可对任意历史时间点 `at` 复原当时有效的证书。
2. **冻结收件人集合与证书摘要**：冻结在单个目录一致性视图（SQLite WAL）上完成，
   快照含每收件人的证书序列号、证书 SHA-256 摘要、公钥指纹、策略模式与解析状态，
   整体再做 SHA-256 摘要。**同一邮件只能冻结一次**，不可重冻、不可修改。
3. **全部强制加密收件人有可信密钥才投递；密钥缺失绝不静默降级**：
   - `ENFORCE`（默认）：无密钥 / 过期 / 撤销 / 未列入通讯录 / CA 不受信 → 整封 `BLOCKED`；
   - `OPPORTUNISTIC`：有可信密钥必须加密（明文授权无效）；确无密钥时，只有发件人
     **逐地址显式确认**（`cleartext_ack`）才允许明文，且明文地址在快照与投递包中留痕。
4. **并发只产生一个完整快照**：轮换 / 撤销 / 通讯录更新 / 发送重试并发时，冻结看到的
   要么是变更前、要么是变更后的完整目录版本，绝不混用；`catalog_version` 单调递增。
5. **旧证书迟到发现不能改变已发送事实**：
   - 冻结后、发送前撤销冻结证书 → fail-closed 转 `BLOCKED`，绝不自动换发，
     只能 `resubmit` 生成**新邮件 + 新快照**；
   - 已 `SENT` 后撤销 → 状态、回执、快照与清单不变，重发幂等。
6. **重试复用同一快照**：传输瞬时失败为 `SEND_FAILED`，重试重放同一信封，
   邮件锁 + 状态 CAS 保证并发重发只有一次真实出站。

## 邮件密码学结构

- 企业根 CA：Ed25519 签发紧凑 JSON 证书（含 X25519 加密公钥 + Ed25519 签名公钥、
  有效期、序列号）；域级信任锚（`domain_trust`），证书链必须由该域受信 CA 签名。
- 混合加密：随机 `body_key` 经 AES-256-GCM 加密正文（AAD = 规范化受保护头，
  含快照摘要）；每收件人一把 X25519 临时密钥 ECDH + HKDF（salt = 快照摘要）
  派生 KEK 封装 `body_key`，封装 AAD 绑定证书序列号。
- 发件人用冻结时证书的 Ed25519 私钥对 `受保护头 ‖ 密文` 签名。
- 全显式明文邮件（无任何加密收件人）使用 `alg=NONE-EXPLICIT-CLEARTEXT`，
  发件人仍对明文签名，且明文地址必须全部在 `cleartext_ack` 中。

## 目录结构

```
app/crypto.py    原语：CA、证书签发/校验、混合加密封装、解封验签
app/policy.py    时间点证书解析、ENFORCE/OPPORTUNISTIC 判定、快照构造/摘要
app/storage.py   SQLite(WAL)：证书版本/撤销追加、快照冻结、状态 CAS、HMAC 审计链
app/gateway.py   编排：生命周期、并发锁、fail-closed 发送、可验证清单
app/api.py       FastAPI 策略 API
app/static/      发送预检页面（四标签页）
tests/           24 个测试（含并发轮换/撤销、篡改检测、真实解封）
demo.py          八个策略场景的端到端演练
```

## 快速开始

```bash
pip install -r requirements.txt
python3 -m pytest -q            # 24 passed
python3 demo.py                 # 命令行演练全部策略场景
uvicorn app.api:app --host 0.0.0.0 --port 8000   # 打开 http://localhost:8000
```

## 策略 API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/cas` | 创建企业根 CA（Ed25519） |
| PUT | `/api/domains/{domain}/trust` | 绑定域 → 受信 CA |
| PUT | `/api/domains/{domain}/policy` | `ENFORCE` / `OPPORTUNISTIC` |
| POST | `/api/identities` | 签发托管身份（生成密钥+证书+入通讯录） |
| POST | `/api/identities/rotate` | 证书轮换（旧证标 superseded，版本留存） |
| POST | `/api/certificates` | 通讯录更新：导入受信 CA 签发的外部证书 |
| POST | `/api/certificates/revoke` | 撤销证书（只追加，不删除） |
| POST | `/api/directory/update` | 通讯录下架 |
| POST | `/api/precheck` | **发送预检**（只读，不冻结不发送，支持 `at` 时间点） |
| POST | `/api/mails` | 创建邮件（支持幂等键） |
| POST | `/api/mails/{id}/freeze` | **冻结收件人集合 + 完整密钥快照** |
| POST | `/api/mails/{id}/send` | 按冻结快照投递（423=策略阻断, 503=传输瞬时失败可重试） |
| POST | `/api/mails/{id}/resubmit` | 阻断后以当前目录新密钥重新提交（新邮件/新快照） |
| GET | `/api/mails/{id}/manifest` | **可验证投递清单**（`verify=true` 执行全部密码学校验） |
| GET | `/api/audit` · `/api/audit/verify` | HMAC 防篡改审计哈希链 |

### 典型调用序列

```bash
# 1) 基础设施
curl -X POST localhost:8000/api/cas -d '{"ca_id":"corp-root"}'
curl -X PUT  localhost:8000/api/domains/corp.example/trust \
     -d '{"domain":"corp.example","ca_id":"corp-root"}'
curl -X POST localhost:8000/api/identities \
     -d '{"email":"alice@corp.example","ca_id":"corp-root"}'
curl -X POST localhost:8000/api/identities \
     -d '{"email":"bob@corp.example","ca_id":"corp-root"}'

# 2) 预检
curl -X POST localhost:8000/api/precheck \
     -d '{"recipients":[{"email":"bob@corp.example"}]}'

# 3) 创建 → 冻结 → 发送
MID=$(curl -s -X POST localhost:8000/api/mails \
  -d '{"sender":"alice@corp.example","subject":"s","body":"机密"}' | jq -r .id)
curl -X POST localhost:8000/api/mails/$MID/freeze \
     -d '{"recipients":[{"email":"bob@corp.example"}]}'
curl -X POST localhost:8000/api/mails/$MID/send

# 4) 可验证清单（逐收件人真实解封 + 发件人验签 + 审计链）
curl localhost:8000/api/mails/$MID/manifest | jq .verification
```

## 可验证投递清单检查项

`snapshot_digest_match`（冻结载荷摘要=邮件登记摘要）、
`recipient_count_match`、`all_enforced_recipients_encrypted`、
`no_silent_downgrade`（明文地址必须在显式 ack 集合内）、
`spool_digest_match`（出站密文保护头绑定快照摘要）、
`envelopes_match_snapshot`（每把密钥信封的证书指纹集合=快照中的 TRUSTED 集合）、
`cleartext_matches_ack`、`sender_signed`、
`content_integrity`（用每个冻结证书对应的私钥真实解密封装并比对正文、
验证发件人 Ed25519 签名）、`audit_chain.ok`（HMAC 哈希链），
汇总为布尔 `overall_valid`。

## 邮件状态机

```
DRAFT ──freeze──▶ READY ──send OK──▶ SENT（终态，重发幂等）
  │                 │
  │                 ├──传输瞬时故障──▶ SEND_FAILED ──send──▶ SENT（同一快照）
  │                 └──冻结后撤销────▶ BLOCKED（fail-closed，只能 resubmit）
  └──freeze（密钥不满足）──────────▶ BLOCKED ──resubmit──▶ 新 DRAFT
```

## 生产化注意（本实现边界）

- 托管身份私钥以明文 PEM 存 SQLite；生产应替换为 KMS/HSM（`Store` 的
  `cert_private_keys` 读写为唯一边界）。
- 传输层 `SpoolTransport` 为落盘模拟；对接真实 MTA 时实现 `Transport.send`，
  保持“先快照后投递、回执原子落库”的顺序即可。
- CA 签发密钥保存在网关进程内存；多副本部署需外置签发服务与互斥。
