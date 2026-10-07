#!/usr/bin/env python3
"""端到端策略演练脚本（不落库，内存运行）。

依次演示：
1. 建 CA / 域信任 / 托管身份；
2. 正常加密投递 + 可验证清单；
3. 强制域密钥缺失 → 阻断，无静默降级；
4. 冻结后并发轮换 → 发送仍用旧快照；
5. 冻结后、发送前撤销 → fail-closed 阻断；
6. 发送后撤销 → 已发送事实不变；
7. 传输瞬时故障重试复用同一快照；
8. 机会加密域：无 ack 阻断、显式 ack 明文留痕。
"""
from __future__ import annotations

import json
import tempfile

from app.gateway import Gateway, SpoolTransport
from app.storage import Store


class Clock:
    def __init__(self):
        self.t = 1_760_000_000.0

    def __call__(self):
        return self.t

    def tick(self, dt=60):
        self.t += dt


def main():
    clk = Clock()
    gw = Gateway(Store(":memory:", clock=clk),
                 SpoolTransport(tempfile.mkdtemp(), clock=clk))

    def line(title):
        print("\n" + "=" * 72 + f"\n{title}\n" + "-" * 72)

    # ---- 1. 基础设施
    line("1. 建立企业 CA / 域信任 / 托管身份")
    gw.create_ca("corp-root")
    gw.create_ca("partner-root")
    gw.set_domain_trust("corp.example", "corp-root")
    gw.set_domain_trust("partner.example", "partner-root")
    gw.issue_identity("alice@corp.example", "corp-root")
    gw.issue_identity("bob@corp.example", "corp-root")
    gw.issue_identity("carol@partner.example", "partner-root")
    print("已签发 alice/bob@corp.example、carol@partner.example")

    # ---- 2. 正常投递
    line("2. 正常端到端加密投递")
    mail = gw.create_mail(sender="alice@corp.example",
                          subject="Q4 机密财报", body="营收 +32%，机密")
    frozen = gw.freeze(mail["id"], [
        {"email": "bob@corp.example"},
        {"email": "carol@partner.example"},
    ])
    print(f"冻结快照 {frozen['snapshot_digest'][:32]}… "
          f"@目录版本 {frozen['catalog_version']}")
    sent = gw.send(mail["id"])
    print(f"投递结果: {sent['status']}  回执: {sent['spool_receipt']}")
    mf = gw.build_manifest(mail["id"])
    print("清单自动校验:", json.dumps(
        {k: v for k, v in mf["verification"].items()
         if not isinstance(v, (dict, list))}, ensure_ascii=False, indent=2))

    # ---- 3. 密钥缺失
    line("3. 强制加密域收件人无密钥 → 阻断（不静默降级）")
    with gw.store._wlock:
        gw.store.conn.execute(
            "INSERT OR REPLACE INTO directory_entries(email,listed,updated_at) "
            "VALUES('dave@corp.example',1,?)", (gw.store.now(),))
        gw.store.conn.commit()
    m3 = gw.create_mail(sender="alice@corp.example", subject="x", body="y")
    f3 = gw.freeze(m3["id"], [{"email": "dave@corp.example"}])
    print(f"冻结状态: {f3['status']}  原因: {f3['block_reason']}")
    print("发送尝试:", gw.send(m3["id"])["status"])

    # ---- 4. 冻结后轮换
    line("4. 快照冻结后轮换收件人证书：发送仍严格使用冻结快照")
    m4 = gw.create_mail(sender="alice@corp.example", subject="x", body="y4")
    f4 = gw.freeze(m4["id"], [{"email": "carol@partner.example"}])
    old_fp = f4["recipients"][0]["cert_fp"]
    clk.tick()
    new_cert = gw.rotate_identity("carol@partner.example", "partner-root")
    s4 = gw.send(m4["id"])
    env = gw.store.get_spool(m4["id"])["message"]["encrypted"]["envelopes"]
    print(f"冻结证书 fp: {old_fp[:20]}…")
    from app.crypto import certificate_fingerprint
    print(f"新证书 fp:   {certificate_fingerprint(new_cert)[:20]}…")
    print(f"实际信封 fp: {env[0]['cert_fp'][:20]}…  投递: {s4['status']}")
    assert env[0]["cert_fp"] == old_fp

    # ---- 5. 冻结后撤销（发送前）
    line("5. 冻结后、发送前证书被撤销：fail-closed 阻断")
    m5 = gw.create_mail(sender="alice@corp.example", subject="x", body="y5")
    f5 = gw.freeze(m5["id"], [{"email": "bob@corp.example"}])
    gw.revoke_certificate(f5["recipients"][0]["cert_serial"])
    r5 = gw.send(m5["id"])
    print(f"发送结果: {r5['status']}  原因: {r5['block_reason']}")

    # ---- 6. 发送后撤销
    line("6. 已发送后撤销：旧证书迟到发现不能改变已发送事实")
    m6 = gw.create_mail(sender="alice@corp.example", subject="x", body="y6")
    f6 = gw.freeze(m6["id"], [{"email": "carol@partner.example"}])
    s6 = gw.send(m6["id"])
    gw.revoke_certificate(f6["recipients"][0]["cert_serial"])
    again = gw.send(m6["id"])
    print(f"首次: {s6['status']}/{s6['spool_receipt']}  "
          f"撤销后再查: {again['status']}/{again['spool_receipt']}（回执不变）")
    mf6 = gw.build_manifest(m6["id"])
    print("清单整体有效:", mf6["verification"]["overall_valid"])

    # ---- 7. 重试
    line("7. 传输瞬时故障：重试复用同一完整快照")
    # bob 的旧证已在场景 5 撤销，重新签发
    gw.issue_identity("bob@corp.example", "corp-root")
    m7 = gw.create_mail(sender="alice@corp.example", subject="x", body="y7")
    gw.freeze(m7["id"], [{"email": "bob@corp.example"}])
    gw.transport.once_fail.add(m7["id"])
    a = gw.send(m7["id"])
    b = gw.send(m7["id"])
    print(f"第一次: {a['status']} ({a['last_error']})  第二次: {b['status']} {b['spool_receipt']}")

    # ---- 8. 机会加密
    line("8. 机会加密域：无显式确认阻断；显式确认才允许明文并留痕")
    gw.set_domain_policy("partner.example", "OPPORTUNISTIC")
    with gw.store._wlock:
        gw.store.conn.execute(
            "INSERT OR REPLACE INTO directory_entries(email,listed,updated_at) "
            "VALUES('erin@partner.example',1,?)", (gw.store.now(),))
        gw.store.conn.commit()
    m8 = gw.create_mail(sender="alice@corp.example", subject="x", body="y8")
    f8 = gw.freeze(m8["id"], [{"email": "erin@partner.example"}])
    print(f"无 ack: {f8['status']} / {f8['recipients'][0]['state']}")
    m9 = gw.create_mail(sender="alice@corp.example", subject="x", body="y8",
                        cleartext_ack=["erin@partner.example"])
    f9 = gw.freeze(m9["id"], [
        {"email": "erin@partner.example", "cleartext_ack": True}])
    s9 = gw.send(m9["id"])
    sp = gw.store.get_spool(m9["id"])["message"]
    print(f"显式 ack: {f9['status']} → {s9['status']}；"
          f"明文收件人留痕: {sp['cleartext_recipients']}；密钥信封数: "
          f"{len(sp['encrypted']['envelopes'])}")

    line("审计哈希链校验")
    print(json.dumps(gw.store.verify_audit_chain(), ensure_ascii=False))


if __name__ == "__main__":
    main()
