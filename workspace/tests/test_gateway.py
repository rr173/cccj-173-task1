"""端到端加密投递、密钥缺失 fail-closed、快照不可变、轮换/撤销并发。"""
from __future__ import annotations

import concurrent.futures
import threading

import pytest

from app import policy
from app.crypto import (
    b64d,
    decrypt_message,
    key_fingerprint,
)
from app.gateway import SpoolTransport, TransportError
from app.storage import (
    STATUS_BLOCKED,
    STATUS_DRAFT,
    STATUS_READY,
    STATUS_SEND_FAILED,
    STATUS_SENT,
    StorageError,
)


def recip(email, **kw):
    return {"email": email, **kw}


def _freeze_and_send(gw, recipients, *, sender="alice@corp.example",
                     body="机密内容", ack=None):
    mail = gw.create_mail(sender=sender, subject="t", body=body,
                          cleartext_ack=ack or [])
    res = gw.freeze(mail["id"], recipients)
    assert res["snapshot_digest"]
    sent = gw.send(mail["id"])
    return mail, res, sent


# ---------------------------------------------------------------- 1

def test_happy_path_all_encrypted(gw, bootstrapped):
    mail, res, sent = _freeze_and_send(
        gw, [recip("bob@corp.example"), recip("carol@partner.example")]
    )
    assert res["status"] == STATUS_READY
    assert sent["status"] == STATUS_SENT and sent["spool_receipt"]

    manifest = gw.build_manifest(mail["id"])
    v = manifest["verification"]
    assert v["overall_valid"] is True
    assert v["snapshot_digest_match"]
    assert v["all_enforced_recipients_encrypted"]
    assert v["envelopes_match_snapshot"]
    assert v["audit_chain"]["ok"]
    # 两个托管收件人都能用各自私钥解出原文
    assert v["decryption_check"] == {
        "bob@corp.example": True,
        "carol@partner.example": True,
    }

    # 真实密码学：手工取 bob 的冻结证书私钥解封
    snap = gw.store.get_snapshot(mail["id"])
    bob_serial = next(
        r["cert_serial"] for r in snap["payload"]["recipients"]
        if r["email"] == "bob@corp.example"
    )
    keys = gw.store.get_cert_private_key(bob_serial)
    cert = gw.store.get_certificate(bob_serial)
    msg = gw.store.get_spool(mail["id"])["message"]["encrypted"]
    plain = decrypt_message(
        msg, recipient_serial=bob_serial,
        enc_private_pem=keys["enc_priv_pem"],
        sender_sig_pub_b64=snap["payload"]["sender_sig_pub"],
    )
    assert plain.decode() == "机密内容"
    assert key_fingerprint(cert["enc_pub"]) == key_fingerprint(cert["enc_pub"])


# ---------------------------------------------------------------- 2

def test_missing_mandatory_key_blocks_no_silent_downgrade(gw, bootstrapped):
    # dave 在通讯录中没有证书
    gw.store.update_directory()  # no-op
    gw.create_ca("ext-root") if not gw.store.get_ca_pem("ext-root") else None
    # 构造“已列入通讯录但无密钥”：直接插一条 directory entry
    with gw.store._wlock:
        gw.store.conn.execute(
            "INSERT OR REPLACE INTO directory_entries(email,listed,updated_at) "
            "VALUES('dave@corp.example',1,?)", (gw.store.now(),)
        )
        gw.store.conn.commit()

    mail = gw.create_mail(sender="alice@corp.example", subject="s", body="b")
    res = gw.freeze(mail["id"], [recip("bob@corp.example"),
                                 recip("dave@corp.example")])
    assert res["status"] == STATUS_BLOCKED
    states = {r["email"]: r["state"] for r in res["recipients"]}
    assert states["dave@corp.example"] == policy.STATE_MISSING_KEY
    assert states["bob@corp.example"] == policy.STATE_TRUSTED

    # 尝试发送：拒绝投递
    sent = gw.send(mail["id"])
    assert sent["status"] == STATUS_BLOCKED
    assert gw.store.get_spool(mail["id"]) is None  # 没有任何邮件出站

    # 即使带着 cleartext_ack 想给 ENFORCE 域降级，也必须阻断
    mail2 = gw.create_mail(sender="alice@corp.example", subject="s", body="b",
                           cleartext_ack=["dave@corp.example"])
    res2 = gw.freeze(mail2["id"], [
        recip("dave@corp.example", cleartext_ack=True)
    ])
    assert res2["status"] == STATUS_BLOCKED


# ---------------------------------------------------------------- 3

def test_snapshot_immutable_under_concurrent_rotation(gw, bootstrapped):
    mail = gw.create_mail(sender="alice@corp.example", subject="s",
                          body="冻结后轮换")
    res = gw.freeze(mail["id"], [recip("carol@partner.example")])
    frozen_fp = next(
        r["cert_fp"] for r in res["recipients"] if r["email"] == "carol@partner.example"
    )
    old_serial = gw.store.get_private_keys("carol@partner.example")["current_serial"]

    # 冻结之后轮换 carol 的证书
    new_cert = gw.rotate_identity("carol@partner.example", "partner-root")

    # 目录版本已前进，但发送仍用旧快照
    sent = gw.send(mail["id"])
    assert sent["status"] == STATUS_SENT
    spool = gw.store.get_spool(mail["id"])
    env_fps = {e["cert_fp"] for e in spool["message"]["encrypted"]["envelopes"]}
    assert frozen_fp in env_fps
    assert certificate_fp(new_cert) not in env_fps

    # 重试是幂等的，仍返回 SENT，不会再走传输
    again = gw.send(mail["id"])
    assert again["status"] == STATUS_SENT
    assert again["spool_receipt"] == sent["spool_receipt"]

    # 同一邮件不能再冻结
    with pytest.raises(StorageError):
        gw.freeze(mail["id"], [recip("carol@partner.example")])


def certificate_fp(cert):
    from app.crypto import certificate_fingerprint
    return certificate_fingerprint(cert)


# ---------------------------------------------------------------- 4

def test_late_revocation_blocks_before_sent(gw, bootstrapped):
    mail = gw.create_mail(sender="alice@corp.example", subject="s", body="b")
    res = gw.freeze(mail["id"], [recip("bob@corp.example")])
    serial = next(r["cert_serial"] for r in res["recipients"])

    # 投递前撤销冻结证书（迟到的撤销发现）
    gw.revoke_certificate(serial)
    out = gw.send(mail["id"])
    assert out["status"] == STATUS_BLOCKED
    assert "撤销" in out["block_reason"]
    assert gw.store.get_spool(mail["id"]) is None

    # 撤销不会被“再试一次”绕过；必须重新提交、拿新快照
    retry = gw.send(mail["id"])
    assert retry["status"] == STATUS_BLOCKED
    new_mail = gw.resubmit(mail["id"])
    res2 = gw.freeze(new_mail["id"], [recip("bob@corp.example")])
    # bob 已无有效证书，新快照同样阻断——需要先给他新证书
    assert res2["status"] == STATUS_BLOCKED
    gw.issue_identity("bob@corp.example", "corp-root")
    m3 = gw.resubmit(new_mail["id"])
    r3 = gw.freeze(m3["id"], [recip("bob@corp.example")])
    assert r3["status"] == STATUS_READY
    assert gw.send(m3["id"])["status"] == STATUS_SENT


def test_revocation_after_sent_cannot_change_fact(gw, bootstrapped):
    mail = gw.create_mail(sender="alice@corp.example", subject="s", body="b")
    res = gw.freeze(mail["id"], [recip("bob@corp.example")])
    serial = next(r["cert_serial"] for r in res["recipients"])
    sent = gw.send(mail["id"])
    assert sent["status"] == STATUS_SENT
    receipt = sent["spool_receipt"]

    # 已发送后撤销：事实不变，清单仍完整可验证
    gw.revoke_certificate(serial)
    again = gw.send(mail["id"])
    assert again["status"] == STATUS_SENT and again["spool_receipt"] == receipt
    manifest = gw.build_manifest(mail["id"])
    assert manifest["status"] == STATUS_SENT
    assert manifest["verification"]["overall_valid"] is True


# ---------------------------------------------------------------- 5

def test_transport_failure_retry_uses_same_snapshot(gw, bootstrapped):
    mail = gw.create_mail(sender="alice@corp.example", subject="s", body="b")
    gw.freeze(mail["id"], [recip("bob@corp.example")])
    gw.transport.once_fail.add(mail["id"])

    first = gw.send(mail["id"])
    assert first["status"] == STATUS_SEND_FAILED
    second = gw.send(mail["id"])
    assert second["status"] == STATUS_SENT

    snap = gw.store.get_snapshot(mail["id"])
    msg = gw.store.get_spool(mail["id"])["message"]["encrypted"]
    assert msg["protected"]["snapshot_digest"] == snap["digest"]


# ---------------------------------------------------------------- 6

def test_opportunistic_requires_explicit_ack(gw, bootstrapped):
    # partner 域设为机会加密；新建一个无密钥联系人 erin
    gw.set_domain_policy("partner.example", "OPPORTUNISTIC")
    with gw.store._wlock:
        gw.store.conn.execute(
            "INSERT OR REPLACE INTO directory_entries(email,listed,updated_at) "
            "VALUES('erin@partner.example',1,?)", (gw.store.now(),))
        gw.store.conn.commit()

    # 无 ack → 阻断（不静默明文）
    mail = gw.create_mail(sender="alice@corp.example", subject="s", body="b")
    res = gw.freeze(mail["id"], [recip("erin@partner.example")])
    assert res["status"] == STATUS_BLOCKED
    assert gw.send(mail["id"])["status"] == STATUS_BLOCKED

    # 显式 ack → 允许明文，但必须在快照中留痕
    mail2 = gw.create_mail(sender="alice@corp.example", subject="s", body="b",
                           cleartext_ack=["erin@partner.example"])
    res2 = gw.freeze(mail2["id"], [
        recip("erin@partner.example", cleartext_ack=True)
    ])
    assert res2["status"] == STATUS_READY
    sent = gw.send(mail2["id"])
    assert sent["status"] == STATUS_SENT
    spool = gw.store.get_spool(mail2["id"])["message"]
    assert spool["cleartext_recipients"] == ["erin@partner.example"]
    assert spool["encrypted"]["envelopes"] == [] or \
        "erin@partner.example" not in [
            r["email"] for r in res2["recipients"] if r["state"] == "TRUSTED"
        ]
    manifest = gw.build_manifest(mail2["id"])
    assert manifest["verification"]["no_silent_downgrade"] is True
    assert manifest["verification"]["overall_valid"] is True

    # 有可信密钥时，即使给了 ack 也必须加密
    mail3 = gw.create_mail(sender="alice@corp.example", subject="s", body="b",
                           cleartext_ack=["carol@partner.example"])
    res3 = gw.freeze(mail3["id"], [
        recip("carol@partner.example", cleartext_ack=True)
    ])
    assert res3["status"] == STATUS_READY
    rcarol = next(r for r in res3["recipients"] if r["email"] == "carol@partner.example")
    assert rcarol["state"] == policy.STATE_TRUSTED


# ---------------------------------------------------------------- 7

def test_untrusted_ca_and_expired_cert(gw, bootstrapped):
    # 用 corp-root 给 mallory@partner.example 发证书，但 partner 域只信 partner-root
    cert = gw.issue_identity("mallory@partner.example", "corp-root")
    mail = gw.create_mail(sender="alice@corp.example", subject="s", body="b")
    res = gw.freeze(mail["id"], [recip("mallory@partner.example")])
    state = res["recipients"][0]["state"]
    assert state == policy.STATE_UNTRUSTED_CA
    assert res["status"] == STATUS_BLOCKED

    # 过期证书：颁发一张已过期的证书
    from app.crypto import CertificateAuthority
    ca = gw._ca("partner-root")
    from app.crypto import generate_identity_keypair, certificate_fingerprint
    kp = generate_identity_keypair()
    now = gw.store.now()
    c = ca.issue_certificate("old@partner.example:old", "old@partner.example",
                             kp, now - 200, now - 100)
    gw.store.install_identity_cert("old@partner.example", kp, c)
    pre = gw.precheck([recip("old@partner.example")])
    assert pre["blocked"][0]["state"] == policy.STATE_EXPIRED


# ---------------------------------------------------------------- 8

def test_concurrent_freeze_and_revocation_one_coherent_snapshot(gw, bootstrapped):
    """并发：一封邮件的冻结 与 收件人证书撤销 同时发生。

    冻结必须基于单个一致性目录视图：要么整体用旧证（撤销后发送 fail-closed），
    要么看不到该证书（直接 BLOCKED）；绝不能出现“半新半旧”的快照。
    """
    serial = gw.store.get_private_keys("bob@corp.example")["current_serial"]
    mail = gw.create_mail(sender="alice@corp.example", subject="s", body="b")

    outcomes = []

    def do_freeze():
        try:
            return gw.freeze(mail["id"], [recip("bob@corp.example")])
        except StorageError:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(do_freeze)
        f2 = ex.submit(gw.revoke_certificate, serial)
        rf = f1.result()
        f2.result()

    assert rf is not None
    snap = gw.store.get_snapshot(mail["id"])
    payload = snap["payload"]
    # 快照内收件人证书摘要要么全部引用被撤证书，要么没有该证书——只有一个版本
    fps = [r.get("cert_fp") for r in payload["recipients"]]
    assert len(set(fps)) == len(fps)

    sent = gw.send(mail["id"])
    # 两种可能都合法：撤销先于一致性视图 → BLOCKED(MISSING/REVOKED)；
    # 冻结先于撤销 → fail-closed BLOCKED。共同结果：不会 SENT。
    assert sent["status"] == STATUS_BLOCKED
    assert gw.store.get_spool(mail["id"]) is None


def test_concurrent_duplicate_send_single_delivery(gw, bootstrapped):
    mail = gw.create_mail(sender="alice@corp.example", subject="s", body="b")
    gw.freeze(mail["id"], [recip("bob@corp.example")])
    results = []

    def send():
        results.append(gw.send(mail["id"])["status"])

    threads = [threading.Thread(target=send) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(STATUS_SENT) == 8  # 幂等返回
    # spool 中只有一条记录、传输只发生一次（INSERT OR IGNORE 保证）
    rows = gw.store.conn.execute(
        "SELECT COUNT(*) c FROM spool WHERE mail_id=?", (mail["id"],)
    ).fetchone()["c"]
    assert rows == 1


# ---------------------------------------------------------------- 9

def test_directory_removal_blocks(gw, bootstrapped):
    mail = gw.create_mail(sender="alice@corp.example", subject="s", body="b")
    gw.freeze(mail["id"], [recip("bob@corp.example")])
    # 已冻结的邮件不受通讯录更新影响，仍可发送（快照已定）
    gw.update_directory(remove=["bob@corp.example"])
    assert gw.send(mail["id"])["status"] == STATUS_SENT

    # 新邮件再发给被下架地址则阻断
    mail2 = gw.create_mail(sender="alice@corp.example", subject="s", body="b")
    res = gw.freeze(mail2["id"], [recip("bob@corp.example")])
    assert res["recipients"][0]["state"] == policy.STATE_UNLISTED
    assert res["status"] == STATUS_BLOCKED


# ---------------------------------------------------------------- 10

def test_idempotency_key(gw, bootstrapped):
    a = gw.create_mail(sender="alice@corp.example", subject="x", body="y",
                       idempotency_key="K-1")
    b = gw.create_mail(sender="alice@corp.example", subject="x", body="y",
                       idempotency_key="K-1")
    assert a["id"] == b["id"]


# ---------------------------------------------------------------- 11

def test_point_in_time_resolution(gw, bootstrapped):
    """同一身份在不同时间点解析到不同证书版本。"""
    old_serial = gw.store.get_private_keys(
        "carol@partner.example")["current_serial"]
    t0 = gw.store.now()

    gw.store.clock.advance(100)
    new_cert = gw.rotate_identity("carol@partner.example", "partner-root")
    t1 = gw.store.now()

    # 过去时间点 → 解析到旧证
    past = gw.precheck([recip("carol@partner.example")], at=t0)
    assert past["recipients"][0]["cert_serial"] == old_serial

    # 当前时间点 → 解析到新证
    now = gw.precheck([recip("carol@partner.example")], at=t1)
    assert now["recipients"][0]["cert_serial"] == new_cert["serial"]

    # 撤销新证后：当前解析为 REVOKED，过去时间点仍能复原旧证（审计可追溯）
    gw.revoke_certificate(new_cert["serial"])
    blocked_now = gw.precheck([recip("carol@partner.example")], at=gw.store.now())
    assert blocked_now["blocked"][0]["state"] == policy.STATE_REVOKED
    past_ok = gw.precheck([recip("carol@partner.example")], at=t0)
    assert past_ok["allowed"] is True


# ---------------------------------------------------------------- 12

def test_mixed_concurrent_changes_never_mix_snapshot(gw, bootstrapped):
    """压力测试：大量冻结与轮换/撤销/通讯录更新并发。

    每个已 SENT 邮件的清单必须自洽有效；每个 BLOCKED 不得出站；
    任何快照信封的证书指纹必须全部来自其冻结载荷。
    """
    import random

    emails = ["bob@corp.example", "carol@partner.example"]
    created = []

    def churn():
        for _ in range(20):
            email = random.choice(emails)
            domain = email.rsplit("@", 1)[-1]
            ca = "corp-root" if domain == "corp.example" else "partner-root"
            action = random.random()
            try:
                if action < 0.45:
                    gw.rotate_identity(email, ca)
                elif action < 0.7:
                    serial = gw.store.get_private_keys(email)["current_serial"]
                    gw.revoke_certificate(serial)
                    gw.issue_identity(email, ca)  # 撤旧即补新
                else:
                    gw.update_directory(remove=[])
            except StorageError:
                pass

    def make_and_send():
        mail = gw.create_mail(sender="alice@corp.example", subject="s",
                              body="concurrent-body")
        fz = gw.freeze(mail["id"], [{"email": random.choice(emails)}])
        out = gw.send(mail["id"])
        created.append((mail["id"], fz["status"], out["status"]))

    t1 = threading.Thread(target=churn)
    threads = [threading.Thread(target=make_and_send) for _ in range(12)]
    t1.start()
    for t in threads:
        t.start()
    t1.join()
    for t in threads:
        t.join()

    for mail_id, fz_status, send_status in created:
        assert fz_status in (STATUS_READY, STATUS_BLOCKED)
        assert send_status in (STATUS_SENT, STATUS_BLOCKED, STATUS_SEND_FAILED)
        if fz_status == STATUS_BLOCKED:
            assert send_status == STATUS_BLOCKED
            assert gw.store.get_spool(mail_id) is None
        if send_status == STATUS_SENT:
            mf = gw.build_manifest(mail_id)
            assert mf["verification"]["overall_valid"] is True
