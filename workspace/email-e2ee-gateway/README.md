# 企业邮件端到端加密策略网关（Email E2EE Policy Gateway）

发送前按 **收件人域 / 身份 / 时间点** 解析可用加密证书，**冻结收件人集合与证书摘要**；
只有全部 *强制加密* 收件人都有可信密钥时才投递，**密钥缺失绝不静默降级**。
证书轮换、撤销、通讯录更新与发送重试并发时，同一邮件只使用 **一个完整密钥快照**；
旧证书迟到发现不能改变已发送事实。提供 **策略 API、发送预检页面、可验证投递清单**。

仅依赖 Python 3.11 标准库 + `openssl` 3 CLI，无任何第三方包。

---

## 一、安全红线与实现映射

| 需求红线 | 实现位置 / 机制 |
|---|---|
| 按收件人域、身份、时间点解析证书 | `service.Gateway._resolve_mode`（identity > domain > 默认）+ `_resolve_at`（目录指针 + 未撤销 + `notBefore/notAfter` 对逻辑时钟判定） |
| 发送前冻结收件人集合与证书摘要 | `precheck()` 生成 `snapshots` 行：`recipients_hash`（收件人集合规范化哈希）、`cert_digest`（地址→指纹规范化哈希）、策略快照、时间点、CEK |
| 强制收件人缺密钥不得投递 | `all_required_keyed=0` → 预检 `deliverable=false`；发送时再次闸门检查，拒绝码 `downgrade_blocked`（HTTP 422） |
| 密钥缺失不静默降级 | 仅 `opportunistic` 收件人可明文，且必须由发送方在 send 请求中给出 `plaintext_ack` 显式确认；确认名单持久化进快照并写入清单 |
| 轮换/通讯录更新并发时只认快照 | 发送循环只按快照中冻结的 `fingerprint` 查证书并封装，**不重新解析目录**；轮换后旧证（active=0）仍可用于已冻结邮件；目录删除条目不影响已冻结指纹 |
| 撤销并发时失败关闭、不换发 | 撤销闸门：冻结指纹若在发送时 `revoked=1` 或已到期 → 快照置 `abandoned` 并提交留痕，错误 `key_revoked/key_expired/cert_gone`，绝不改用新指纹 |
| 同一邮件一个完整密钥快照 | CEK 在预检时生成并冻结（`snapshots.envelope_secret`）；成功后快照 `sent`；显式 `renew=true` 才作废旧快照另起新快照链（`renewed_from`） |
| 发送重试（含并发重试）幂等 | 每邮件一把可重入锁 + `BEGIN IMMEDIATE` 行状态机 `prepared→sent/abandoned`；并发重试时后到者直接返回**同一份已签名清单**，不产生第二次投递/第二条成功记录 |
| 旧证书迟到发现不能改变已发送事实 | 清单文档经网关 RSA-PSS 私钥签名；撤销/轮换照常作用于目录，但只能通过 `events` 接口以"事后事件"**追加**到 `manifests.events_json`，签名文档与哈希不变，验签仍通过 |
| 可验证投递清单 | `GET /api/manifests/<id>/verify`：RSA-PSS 签名、规范哈希、收件人集合哈希、快照绑定、冻结指纹一致性五项独立校验，任何人可用网关公钥验证 |

### 加密方案（真实密码学，非示意）

- 正文：随机 CEK 派生 AES-256-CBC 密钥与 HMAC-SHA256 密钥，**Encrypt-then-MAC**，
  AAD 绑定信封头（防密文被搬移到其他邮件）。
- 逐收件人密钥封装：**RSA-2048-OAEP（SHA-256 + MGF1-SHA256）**。
- 投递清单：**RSA-PSS（SHA-256, saltlen=32）** 对规范化 JSON（排序键、无空白）签名。
- 证书：openssl 签发的 X.509（SAN 含邮箱），指纹取 DER 的 SHA-256。
- 收件人私钥只保存在 `vault/`（真实部署中属于收件人设备，发送路径从不读取）。

---

## 二、目录结构

```
app/
  crypto.py     openssl 封装：证书、RSA-OAEP、AES-CBC+HMAC、RSA-PSS
  db.py         SQLite(WAL) schema、逻辑时钟、网关身份密钥引导、私钥库
  service.py    核心：策略解析 / 预检冻结 / 发送闸门 / 清单签名验证
  api.py        HTTP API（标准库 ThreadingHTTPServer）
  server.py     启动入口 + 演示数据
  web/index.html 发送预检页面（原生 JS，无构建）
demo/run_demo.py  7 个红线场景端到端演示
tests/test_gateway.py  21 个测试（含并发竞态、HTTP 端到端）
```

## 三、运行

```bash
# 无需安装任何依赖（只需系统 openssl）
python3 -m app.server --host 127.0.0.1 --port 8080 --data ./data --seed
# 浏览器打开 http://127.0.0.1:8080/
```

页面四个标签：① 发送预检与投递（含失败注入/重试）② 通讯录与证书（签发/轮换/撤销/逻辑时钟）
③ 加密策略（默认 + 域/身份覆盖）④ 投递清单验证（验签、迟到事件、收件人解密）。

```bash
# 红线场景演示
python3 demo/run_demo.py
# 测试
python3 tests/test_gateway.py        # 或 python3 -m unittest tests.test_gateway -v
```

## 四、策略 API 摘要

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/info` | 网关公钥、逻辑时钟、当前策略 |
| POST | `/api/clock` `{epoch\|null}` | 逻辑时钟（时间点/到期演示） |
| GET/PUT/DELETE | `/api/policies` · PUT `/api/policies/default` | 策略（enforce / opportunistic；identity 优先于 domain） |
| GET | `/api/directory` | 通讯录（地址→当前可信指纹） |
| POST | `/api/directory/provision` `/rotate` `/cert` · POST `/api/certs/revoke` · DELETE `/api/directory/<email>` | 证书生命周期 |
| POST | `/api/precheck` | **冻结密钥快照**；重复预检 409，需 `renew:true` 显式重冻 |
| GET | `/api/snapshots/<id>` | 快照详情 |
| POST | `/api/snapshots/<id>/send` | 按快照发送（撤销/到期闸门、`plaintext_ack`、幂等重试） |
| GET | `/api/manifests/<id>` · `/api/messages/<mid>/manifest` · `/api/manifests/<id>/verify` | 清单查询与验证 |
| POST | `/api/manifests/<id>/events` | 追加迟到事件（不改签名事实） |
| POST | `/api/manifests/<id>/decrypt` | 收件人侧解封解密演示 |
| POST | `/api/simulate/fail-next` | 注入单次投递失败以验证重试 |

### 典型时序

```
precheck ──► snapshot{recipients_hash, cert_digest, CEK, policy@t}(prepared)
                │  （期间目录可能轮换/撤销/更新，发送一律不重读目录）
send ───────► 对每个冻结指纹做撤销/到期闸门
                ├─ 冻结证已撤销/到期/消失 ──► snapshot=abandoned，失败关闭
                ├─ opportunistic 缺密钥且无 ack ──► 422 拒绝（不静默降级）
                └─ 全部通过 ──► 单 CEK 加密 + 逐人 OAEP 封装
                        ──► 投递 ──► PSS 签名清单 ──► snapshot=sent
（此后）迟到撤销/轮换 ──► 仅追加 events，签名与哈希不变
```

## 五、并发控制要点

- SQLite WAL + `busy_timeout`；所有写操作 `BEGIN IMMEDIATE`。
- 每 `message_id` 一把进程内 `RLock`，与数据库事务构成双保险。
- 快照状态机在单事务内迁移；`prepared` 邮件失败可按同一快照重试，
  `sent` 邮件的并发/重试调用只返回既有清单（`idempotent_retry=true`）。
- 已发送邮件禁止重新预检（`already_sent`, 409）；已放弃快照禁止发送（`snapshot_abandoned`, 409）。

## 六、边界与生产化说明

这是一个功能完整、密码学真实的策略网关参考实现。走向生产还应替换/补强：
将自签信任锚换成企业 PKI/证书透明日志校验；CEK 落库应改为 HSM/KMS 封装；
出站写文件处接真实 MTA/SMIME 或 PGP 传输；`vault/` 收件人私钥应只存在于终端；
增加清单的外部时间戳与 Merkle 归档、操作审计与多副本高可用。
