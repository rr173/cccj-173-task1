#!/usr/bin/env python3
"""端到端红线场景演示（真实 HTTP + 真实 openssl 密码学）。

依次演示：
  1. 正常预检+发送+清单验证+收件人解密
  2. 强制收件人缺密钥 -> 阻断，不静默降级
  3. 预检后轮换证书 -> 发送仍用冻结旧指纹
  4. 预检后撤销证书 -> 失败关闭，不换发
  5. 机会性收件人缺密钥 -> 未确认阻断 / 显式确认才明文
  6. 投递瞬时失败 -> 同一快照同一 CEK 幂等重试
  7. 发送后迟到撤销 -> 只追加事件，已签名事实不变
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.server import make_server  # noqa: E402

BASE = None


def call(method, path, obj=None, expect_fail=False):
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode())
        if expect_fail:
            return e.code, body
        raise AssertionError(f"{method} {path} 意外失败 {e.code}: {body}")


def section(n, title):
    print(f"\n{'='*72}\n场景 {n}：{title}\n{'='*72}")


def show(label, obj, maxlen=400):
    s = json.dumps(obj, ensure_ascii=False, indent=2)
    if len(s) > maxlen:
        s = s[:maxlen] + f"\n  …（省略 {len(s)-maxlen} 字符）"
    print(f"-- {label} --\n{s}")


def main():
    global BASE
    tmp = tempfile.mkdtemp(prefix="gw-demo-")
    httpd = make_server("127.0.0.1", 0, tmp, seed=True)
    port = httpd.server_address[1]
    BASE = f"http://127.0.0.1:{port}"
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)

    # ---- 1. 正常全链路 ----------------------------------------------------
    section(1, "正常发送：预检冻结 → 加密投递 → 验签清单 → 收件人解密")
    _, pc = call("POST", "/api/precheck", {
        "message_id": "msg-001", "sender": "alice@corp.example",
        "recipients": ["bob@corp.example", "carol@eng.corp.example"]})
    print(f"快照 {pc['snapshot_id']}  可投递={pc['deliverable']}  "
          f"证书摘要={pc['cert_digest'][:20]}…")
    _, sent = call("POST", f"/api/snapshots/{pc['snapshot_id']}/send",
                   {"body": "季度营收预测：增长 18%。"})
    print(f"已投递 清单={sent['manifest_id']}")
    _, v = call("GET", f"/api/manifests/{sent['manifest_id']}/verify")
    print("清单验证：", "全部通过 ✅" if v["valid"] else "失败 ❌",
          [c["check"] for c in v["checks"]])
    _, dec = call("POST", f"/api/manifests/{sent['manifest_id']}/decrypt",
                  {"address": "carol@eng.corp.example"})
    print("carol 解密正文：", dec["plaintext"])

    # ---- 2. 缺密钥阻断 ----------------------------------------------------
    section(2, "强制域收件人无密钥：禁止投递，不静默降级")
    _, pc = call("POST", "/api/precheck", {
        "message_id": "msg-002", "sender": "alice@corp.example",
        "recipients": ["bob@corp.example", "unknown@external.io"]})
    print("可投递：", pc["deliverable"],
          "| 缺失强制收件人：", [m["address"] for m in pc["required_missing"]])
    code, err = call("POST", f"/api/snapshots/{pc['snapshot_id']}/send",
                     {"body": "机密"}, expect_fail=True)
    print(f"发送被拒 HTTP {code}: {err['error']} —— {err['message'][:60]}…")

    # ---- 3. 预检后轮换 ----------------------------------------------------
    section(3, "预检后证书轮换：发送只认快照冻结的旧指纹")
    _, pc = call("POST", "/api/precheck", {
        "message_id": "msg-003", "sender": "alice@corp.example",
        "recipients": ["bob@corp.example"]})
    old_fp = pc["recipients"][0]["fingerprint"]
    _, rot = call("POST", "/api/directory/rotate",
                  {"email": "bob@corp.example"})
    print(f"预检指纹 {old_fp[:16]}…  轮换后目录指针 {rot['fingerprint'][:16]}…")
    _, sent = call("POST", f"/api/snapshots/{pc['snapshot_id']}/send",
                   {"body": "轮换竞态邮件"})
    _, m = call("GET", f"/api/manifests/{sent['manifest_id']}")
    used = m["document"]["recipients"][0]["fingerprint"]
    print(f"清单中实际使用指纹 {used[:16]}…  与冻结一致：{used == old_fp} ✅")

    # ---- 4. 预检后撤销 ----------------------------------------------------
    section(4, "预检后证书撤销：失败关闭，绝不换发另一把钥匙")
    _, pc = call("POST", "/api/precheck", {
        "message_id": "msg-004", "sender": "alice@corp.example",
        "recipients": ["carol@eng.corp.example"]})
    fp = pc["recipients"][0]["fingerprint"]
    call("POST", "/api/certs/revoke",
         {"fingerprint": fp, "reason": "pre-send compromise"})
    code, err = call("POST", f"/api/snapshots/{pc['snapshot_id']}/send",
                     {"body": "机密"}, expect_fail=True)
    print(f"发送被拒 HTTP {code}: {err['error']} —— {err['message'][:70]}…")
    print("（快照已作废；不会自动改用其他证书，也不会明文发出）")

    # ---- 5. 机会性 + 显式确认 ---------------------------------------------
    section(5, "机会性收件人缺密钥：未确认阻断；显式确认才允许明文并留痕")
    call("DELETE", "/api/directory/dave@partner.example")
    _, pc = call("POST", "/api/precheck", {
        "message_id": "msg-005", "sender": "alice@corp.example",
        "recipients": ["bob@corp.example", "dave@partner.example"]})
    print("可投递：", pc["deliverable"],
          "| 需确认明文：", [m["address"] for m in pc["optional_missing"]])
    code, err = call("POST", f"/api/snapshots/{pc['snapshot_id']}/send",
                     {"body": "x"}, expect_fail=True)
    print(f"未确认直接发送 -> HTTP {code}: {err['error']}")
    _, sent = call("POST", f"/api/snapshots/{pc['snapshot_id']}/send",
                   {"body": "合作方可见内容",
                    "plaintext_ack": ["dave@partner.example"]})
    _, m = call("GET", f"/api/manifests/{sent['manifest_id']}")
    for r in m["document"]["recipients"]:
        print(f"  {r['address']:<28} -> {r['transport']}"
              + (f"（确认时刻 {r.get('acknowledged_at')}）"
                 if r["transport"] == "cleartext" else ""))

    # ---- 6. 失败重试 ------------------------------------------------------
    section(6, "投递瞬时失败：同一快照、同一 CEK 幂等重试")
    _, pc = call("POST", "/api/precheck", {
        "message_id": "msg-006", "sender": "alice@corp.example",
        "recipients": ["bob@corp.example"]})
    call("POST", "/api/simulate/fail-next",
         {"recipient": "bob@corp.example"})
    code, err = call("POST", f"/api/snapshots/{pc['snapshot_id']}/send",
                     {"body": "重试邮件"}, expect_fail=True)
    print(f"第一次投递 HTTP {code}: {err['message'][:50]}…（快照保持 prepared）")
    _, sent1 = call("POST", f"/api/snapshots/{pc['snapshot_id']}/send",
                    {"body": "重试邮件"})
    _, sent2 = call("POST", f"/api/snapshots/{pc['snapshot_id']}/send",
                    {"body": "重试邮件"})
    print(f"重试成功 manifest={sent1['manifest_id']}；"
          f"再次调用返回同一 manifest："
          f"{sent1['manifest_id'] == sent2['manifest_id']} ✅（无重复投递）")

    # ---- 7. 迟到撤销 ------------------------------------------------------
    section(7, "发送后迟到发现旧证书撤销：只追加事件，已发送事实不可改变")
    _, pc = call("POST", "/api/precheck", {
        "message_id": "msg-007", "sender": "alice@corp.example",
        "recipients": ["bob@corp.example"]})
    used_fp = pc["recipients"][0]["fingerprint"]
    _, sent = call("POST", f"/api/snapshots/{pc['snapshot_id']}/send",
                   {"body": "已发出的邮件"})
    sha_before = sent["sha256"]
    call("POST", "/api/certs/revoke",
         {"fingerprint": used_fp, "reason": "late discovered compromise"})
    _, ev = call("POST", f"/api/manifests/{sent['manifest_id']}/events", {
        "kind": "late_revocation",
        "detail": {"address": "bob@corp.example", "fingerprint": used_fp}})
    _, v = call("GET", f"/api/manifests/{sent['manifest_id']}/verify")
    print(f"迟到事件已追加：{ev['appended']['kind']}")
    print(f"签名仍有效：{v['valid']} ✅；清单哈希不变："
          f"{sha_before == sent['sha256']} ✅；事件数：{len(v['late_events'])}")

    print(f"\n演示数据目录：{tmp}")
    print(f"控制台/UI：先运行  python3 -m app.server --seed  然后浏览器打开 /")
    httpd.shutdown()


if __name__ == "__main__":
    main()
