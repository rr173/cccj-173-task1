"""防篡改与密码学边界测试。"""
import json

import pytest

from app.crypto import (
    canonical,
    certificate_fingerprint,
    decrypt_message,
    generate_identity_keypair,
    InvalidCertificate,
    verify_certificate,
    load_ed25519_public_pem,
)
from app import policy


def test_tampered_snapshot_digest_fails(gw, bootstrapped):
    mail = gw.create_mail(sender="alice@corp.example", subject="s", body="b")
    gw.freeze(mail["id"], [{"email": "bob@corp.example"}])
    gw.send(mail["id"])

    # 直接篡改快照载荷（模拟存储被改）
    row = gw.store.conn.execute(
        "SELECT payload_json FROM snapshots WHERE mail_id=?", (mail["id"],)
    ).fetchone()
    payload = json.loads(row["payload_json"])
    payload["subject"] = "被篡改的主题"
    gw.store.conn.execute(
        "UPDATE snapshots SET payload_json=? WHERE mail_id=?",
        (json.dumps(payload, ensure_ascii=False), mail["id"]),
    )
    gw.store.conn.commit()
    # 已 SENT 的邮件重发保持幂等（事实不变），但清单必然检出篡改
    manifest = gw.build_manifest(mail["id"])
    assert manifest["verification"]["snapshot_digest_match"] is False
    assert manifest["verification"]["overall_valid"] is False


def test_tampered_audit_chain_detected(gw, bootstrapped):
    assert gw.store.verify_audit_chain()["ok"] is True
    gw.store.conn.execute(
        "UPDATE audit_log SET event='HACKED' WHERE id=1"
    )
    gw.store.conn.commit()
    result = gw.store.verify_audit_chain()
    assert result["ok"] is False
    assert result["broken_at"] >= 1


def test_forged_certificate_rejected(gw, bootstrapped):
    ca_pem = gw.store.get_ca_pem("corp-root")
    bob_rows = [c for c in gw.store.list_certificates("bob@corp.example")]
    cert = dict(bob_rows[0]["cert"])
    cert["enc_pub"] = generate_identity_keypair().enc_pub  # 换公钥
    with pytest.raises(InvalidCertificate):
        verify_certificate(cert, load_ed25519_public_pem(ca_pem))


def test_ciphertext_tampering_breaks_gcm(gw, bootstrapped):
    mail = gw.create_mail(sender="alice@corp.example", subject="s",
                          body="integrity")
    res = gw.freeze(mail["id"], [{"email": "bob@corp.example"}])
    gw.send(mail["id"])
    snap = gw.store.get_snapshot(mail["id"])
    serial = next(r["cert_serial"] for r in snap["payload"]["recipients"]
                  if r["email"] == "bob@corp.example")
    keys = gw.store.get_cert_private_key(serial)
    msg = gw.store.get_spool(mail["id"])["message"]["encrypted"]

    # 正常解封
    plain = decrypt_message(
        msg, recipient_serial=serial, enc_private_pem=keys["enc_priv_pem"],
        sender_sig_pub_b64=snap["payload"]["sender_sig_pub"],
    )
    assert plain == b"integrity"

    # 翻转密文一位 → GCM 认证失败
    tampered = json.loads(json.dumps(msg))
    ct = tampered["ciphertext"]
    tampered["ciphertext"] = ("A" if ct[0] != "A" else "B") + ct[1:]
    with pytest.raises(Exception):
        decrypt_message(
            tampered, recipient_serial=serial,
            enc_private_pem=keys["enc_priv_pem"],
            sender_sig_pub_b64=snap["payload"]["sender_sig_pub"],
        )

    # 错误收件人的私钥无法解封（envelope AAD 绑定序列号）
    alice_serial = gw.store.get_private_keys("alice@corp.example")["current_serial"]
    with pytest.raises(Exception):
        decrypt_message(
            msg, recipient_serial=alice_serial,
            enc_private_pem=gw.store.get_cert_private_key(alice_serial)["enc_priv_pem"],
            sender_sig_pub_b64=snap["payload"]["sender_sig_pub"],
        )


def test_canonical_json_determinism():
    a = canonical({"z": 1, "a": [1, 2, {"k": "v"}]})
    b = canonical({"a": [1, 2, {"k": "v"}], "z": 1})
    assert a == b
