"""网关编排：CA 托管、邮件生命周期、快照冻结、投递与可验证清单。

并发模型：
- 所有目录/证书写操作在 Store 的写锁内串行完成并推进 catalog_version；
- read_catalog 在单个只读事务的一致性快照上读取（WAL），
  因此冻结与轮换/撤销/通讯录更新并发时，每次冻结看到的要么是变更前、
  要么是变更后的完整视图，绝不混用；
- 每封邮件发送时持有该邮件的互斥锁 + 数据库状态 CAS，杜绝并发重复投递；
- 重试只复用已冻结快照；冻结后撤销在 SENT 之前 fail-closed 阻断。
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from typing import Any, Callable, Optional, Protocol

from . import policy
from .crypto import (
    CertificateAuthority,
    b64e,
    certificate_fingerprint,
    decrypt_message,
    ed25519_public_pem,
    encrypt_message,
    generate_identity_keypair,
    key_fingerprint,
    sha256_hex,
)
from .storage import (
    STATUS_BLOCKED,
    STATUS_DRAFT,
    STATUS_READY,
    STATUS_SEND_FAILED,
    STATUS_SENT,
    NotFound,
    StorageError,
    Store,
)

# 审计事件
EV_CA_CREATED = "CA_CREATED"
EV_DOMAIN_TRUST = "DOMAIN_TRUST_SET"
EV_DOMAIN_POLICY = "DOMAIN_POLICY_SET"
EV_IDENTITY_ISSUED = "IDENTITY_ISSUED"
EV_CERT_ROTATED = "CERT_ROTATED"
EV_CERT_PROVISIONED = "CERT_PROVISIONED"
EV_CERT_REVOKED = "CERT_REVOKED"
EV_DIRECTORY_UPDATED = "DIRECTORY_UPDATED"
EV_MAIL_CREATED = "MAIL_CREATED"
EV_SNAPSHOT_FROZEN = "SNAPSHOT_FROZEN"
EV_SEND_BLOCKED = "SEND_BLOCKED"
EV_SEND_FAILED = "SEND_FAILED"
EV_MAIL_SENT = "MAIL_SENT"
EV_RETRY_ABORTED = "RETRY_ABORTED"
EV_MAIL_RESUBMITTED = "MAIL_RESUBMITTED"

REVOKE_BLOCK_REASON = "冻结后撤销：已冻结证书在投递前被撤销，fail-closed 阻断；请用新密钥重新提交"


class Transport(Protocol):
    def send(self, mail_id: str, bundle: dict) -> str:
        """返回投递回执标识；失败抛 TransportError。"""
        ...


class TransportError(Exception):
    def __init__(self, message: str, *, transient: bool = True):
        super().__init__(message)
        self.transient = transient


class SpoolTransport:
    """模拟企业出站 MTA：把投递包落盘到 spool 目录。

    fail_serials/once_fail 用于演练传输故障与重试。
    """

    def __init__(self, spool_dir: str, clock: Callable[[], float] = time.time):
        self.spool_dir = spool_dir
        self.clock = clock
        os.makedirs(spool_dir, exist_ok=True)
        self._lock = threading.Lock()
        self.always_fail: set[str] = set()
        self.once_fail: set[str] = set()

    def send(self, mail_id: str, bundle: dict) -> str:
        with self._lock:
            fail = mail_id in self.always_fail or mail_id in self.once_fail
            self.once_fail.discard(mail_id)
        if fail:
            raise TransportError(f"出站 MTA 暂时不可用: {mail_id}", transient=True)
        receipt = f"SPOOL-{uuid.uuid4().hex[:20]}"
        path = os.path.join(self.spool_dir, f"{mail_id}.json")
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"receipt": receipt, "spooled_at": self.clock(),
                       "bundle": bundle}, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        return receipt


class Gateway:
    def __init__(
        self,
        store: Store,
        transport: Transport,
        *,
        fail_closed_on_revoked: bool = True,
    ):
        self.store = store
        self.transport = transport
        self.fail_closed_on_revoked = fail_closed_on_revoked
        self._cas: dict[str, CertificateAuthority] = {}

    # ----------------------------------------------------------- CA

    def create_ca(self, ca_id: str) -> dict:
        if self.store.get_ca_pem(ca_id):
            raise StorageError(f"CA 已存在: {ca_id}")
        ca = CertificateAuthority.generate(ca_id)
        pem = ca.public_pem()
        fp = ca.fingerprint()
        self.store.create_ca(ca_id, pem, fp)
        self._cas[ca_id] = ca
        self.store.append_audit(EV_CA_CREATED, ca_id, {"fingerprint": fp})
        return {"ca_id": ca_id, "public_pem": pem, "fingerprint": fp}

    def _ca(self, ca_id: str) -> CertificateAuthority:
        ca = self._cas.get(ca_id)
        if ca is None:
            raise StorageError(
                f"CA {ca_id} 的签发密钥不在本网关进程（仅已创建的 CA 可签发）"
            )
        return ca

    # ----------------------------------------------------------- 信任/策略/目录

    def set_domain_trust(self, domain: str, ca_id: str) -> dict:
        self.store.set_domain_trust(domain, ca_id)
        self.store.append_audit(
            EV_DOMAIN_TRUST, domain.lower(), {"ca_id": ca_id}
        )
        return {"domain": domain.lower(), "ca_id": ca_id}

    def set_domain_policy(self, domain: str, mode: str) -> dict:
        self.store.set_domain_policy(domain, mode)
        self.store.append_audit(
            EV_DOMAIN_POLICY, domain.lower(), {"mode": mode}
        )
        return {"domain": domain.lower(), "mode": mode}

    # ----------------------------------------------------------- 身份/证书

    def issue_identity(
        self,
        email: str,
        ca_id: str,
        *,
        ttl_seconds: float = 90 * 86400,
        not_before: Optional[float] = None,
        audit_event: str = EV_IDENTITY_ISSUED,
    ) -> dict:
        ca = self._ca(ca_id)
        email = email.strip().lower()
        kp = generate_identity_keypair()
        nb = self.store.now() if not_before is None else not_before
        serial = f"{email}:{uuid.uuid4().hex[:16]}"
        cert = ca.issue_certificate(serial, email, kp, nb, nb + ttl_seconds)
        self.store.install_identity_cert(email, kp, cert)
        self.store.append_audit(audit_event, email, {
            "ca_id": ca_id, "serial": serial,
            "cert_fp": certificate_fingerprint(cert),
            "key_fp": key_fingerprint(cert["enc_pub"]),
            "not_before": cert["not_before"], "not_after": cert["not_after"],
        })
        return cert

    def rotate_identity(self, email: str, ca_id: str, **kw) -> dict:
        return self.issue_identity(
            email, ca_id, audit_event=EV_CERT_ROTATED, **kw
        )

    def provision_external_cert(self, cert: dict) -> dict:
        installed = self.store.provision_external_cert(cert)
        self.store.append_audit(EV_CERT_PROVISIONED, cert["email"], {
            "ca_id": cert["ca_id"], "serial": cert["serial"],
            "cert_fp": certificate_fingerprint(installed),
        })
        return installed

    def revoke_certificate(self, serial: str) -> dict:
        self.store.revoke_certificate(serial)
        self.store.append_audit(EV_CERT_REVOKED, serial, {})
        return {"serial": serial, "revoked_at": self.store.now()}

    def update_directory(self, *, remove: Optional[list[str]] = None) -> dict:
        self.store.update_directory(remove)
        self.store.append_audit(EV_DIRECTORY_UPDATED, None, {"removed": remove or []})
        return {"removed": remove or []}

    # ----------------------------------------------------------- 邮件

    def create_mail(
        self,
        *,
        sender: str,
        subject: str,
        body: str,
        cleartext_ack: Optional[list[str]] = None,
        idempotency_key: Optional[str] = None,
        resubmit_of: Optional[str] = None,
    ) -> dict:
        sender = sender.strip().lower()
        if not self.store.get_private_keys(sender):
            raise StorageError(
                f"发件人 {sender} 不是网关托管身份，无法代表其签名发信"
            )
        ack = sorted({a.strip().lower() for a in (cleartext_ack or [])})
        if idempotency_key:
            existing = self.store.find_by_idempotency_key(idempotency_key)
            if existing:
                return existing
        mail_id = f"MAIL-{uuid.uuid4().hex[:20]}"
        mail = self.store.create_mail(
            mail_id=mail_id, idempotency_key=idempotency_key,
            sender=sender, subject=subject,
            body_b64=__import__("base64").b64encode(body.encode("utf-8")).decode(),
            cleartext_ack=ack, resubmit_of=resubmit_of,
        )
        self.store.append_audit(
            EV_MAIL_RESUBMITTED if resubmit_of else EV_MAIL_CREATED,
            mail_id, {"sender": sender, "resubmit_of": resubmit_of}
        )
        return mail

    def resubmit(self, old_mail_id: str) -> dict:
        """阻断后用当前目录的新密钥重新提交：新邮件、新快照。"""
        old = self.store.get_mail(old_mail_id)
        import base64

        return self.create_mail(
            sender=old["sender"], subject=old["subject"],
            body=base64.b64decode(old["body_b64"]).decode("utf-8"),
            cleartext_ack=old["cleartext_ack"],
            resubmit_of=old_mail_id,
        )

    # ----------------------------------------------------------- 预检/冻结

    def precheck(self, recipients: list[dict], *, at: Optional[float] = None) -> dict:
        """发送预检：不写入任何数据，返回完整解析与判定（供预检页面调用）。"""
        at = self.store.now() if at is None else at
        catalog = self.store.read_catalog()
        decision = policy.evaluate(recipients, catalog, at)
        return {
            "at": at,
            "catalog_version": catalog["catalog_version"],
            "allowed": decision["allowed"],
            "recipients": [r.to_snapshot() for r in decision["resolutions"]],
            "blocked": [r.to_snapshot() for r in decision["blocked"]],
            "trusted_count": len(decision["trusted"]),
            "cleartext_ack_count": len(decision["cleartext"]),
        }

    def freeze(self, mail_id: str, recipients: list[dict], *, at: Optional[float] = None) -> dict:
        """冻结收件人集合与完整密钥快照；一次目录一致性视图，只允许一个快照。"""
        mail = self.store.get_mail(mail_id)
        if mail["status"] != STATUS_DRAFT:
            raise StorageError(
                f"邮件 {mail_id} 已有冻结快照（状态 {mail['status']}），"
                "同一邮件不能再次冻结；请重新提交新邮件"
            )
        at = self.store.now() if at is None else at

        # 单个一致性目录视图上完成解析与冻结
        catalog = self.store.read_catalog()
        decision = policy.evaluate(recipients, catalog, at)
        sender_keys = self.store.get_private_keys(mail["sender"])
        sender_cert = self.store.get_certificate(sender_keys["current_serial"])
        payload = policy.build_snapshot_payload(
            mail_id=mail_id, sender=mail["sender"],
            sender_cert_serial=sender_cert["serial"],
            sender_sig_pub=sender_cert["sig_pub"],
            subject=mail["subject"],
            body_b64=mail["body_b64"], decision=decision,
        )
        mismatches = policy.verify_snapshot_recipients(payload, decision)
        if mismatches:
            raise StorageError("快照一致性校验失败: " + "; ".join(mismatches))
        digest = policy.snapshot_digest(payload)

        rows = [{
            "email": r.email, "mode": r.mode, "state": r.state,
            "cert_serial": r.cert_serial, "cert_fp": r.cert_fp,
            "key_fp": r.key_fp, "reason": r.reason,
        } for r in decision["resolutions"]]

        if decision["allowed"]:
            status, reason = STATUS_READY, None
        else:
            reasons = sorted({r.state for r in decision["blocked"]})
            status, reason = STATUS_BLOCKED, "强制策略阻断: " + ",".join(reasons)

        self.store.freeze_snapshot(
            mail_id=mail_id, payload=payload, digest=digest,
            recipients=rows, status=status, block_reason=reason,
        )
        self.store.append_audit(EV_SNAPSHOT_FROZEN, mail_id, {
            "snapshot_digest": digest,
            "catalog_version": payload["catalog_version"],
            "frozen_at": payload["frozen_at"],
            "recipients": payload["recipients"],
            "allowed": decision["allowed"],
        })
        if not decision["allowed"]:
            self.store.append_audit(EV_SEND_BLOCKED, mail_id, {
                "snapshot_digest": digest,
                "blocked": [r.to_snapshot() for r in decision["blocked"]],
            })
        return {
            "mail_id": mail_id, "status": status, "block_reason": reason,
            "snapshot_digest": digest,
            "catalog_version": payload["catalog_version"],
            "frozen_at": payload["frozen_at"],
            "recipients": [r.to_snapshot() for r in decision["resolutions"]],
        }

    # ----------------------------------------------------------- 发送

    def send(self, mail_id: str) -> dict:
        """按冻结快照投递。重试复用同一快照；状态 CAS + 邮件锁防并发。"""
        with self.store.mail_lock(mail_id):
            # 锁内重新读取状态，确保并发发送只有一个线程看到 READY
            mail = self.store.get_mail(mail_id)
            if mail["status"] == STATUS_SENT:
                return {"mail_id": mail_id, "status": STATUS_SENT,
                        "spool_receipt": mail["spool_receipt"],
                        "note": "邮件已投递，冻结快照不可改变"}
            if mail["status"] == STATUS_BLOCKED:
                return {"mail_id": mail_id, "status": STATUS_BLOCKED,
                        "block_reason": mail["block_reason"]}
            if mail["status"] not in (STATUS_READY, STATUS_SEND_FAILED):
                raise StorageError(f"邮件状态 {mail['status']} 不可投递")

            snapshot = self.store.get_snapshot(mail_id)
            if snapshot is None:
                raise StorageError("冻结快照缺失")
            payload = snapshot["payload"]
            if policy.snapshot_digest(payload) != snapshot["digest"]:
                raise StorageError("冻结快照被篡改：摘要不匹配，fail-closed")
            if snapshot["digest"] != mail["snapshot_digest"]:
                raise StorageError("邮件登记的快照摘要与快照不符，fail-closed")

            # fail-closed：冻结证书在投递前被撤销 → 阻断，绝不换发
            if self.fail_closed_on_revoked:
                revoked = self._revoked_frozen_serials(payload)
                if revoked:
                    self.store.cas_mail_status(
                        mail_id, {STATUS_READY, STATUS_SEND_FAILED},
                        {"status": STATUS_BLOCKED, "block_reason": REVOKE_BLOCK_REASON,
                         "last_attempt_at": self.store.now()},
                    )
                    self.store.append_audit(EV_RETRY_ABORTED, mail_id, {
                        "snapshot_digest": snapshot["digest"],
                        "revoked_serials": revoked,
                    })
                    return self.store.get_mail(mail_id)

            catalog = self.store.read_catalog()
            certs = policy.trusted_certs_from_snapshot(payload, catalog)
            keys = self.store.get_private_keys(mail["sender"])
            import base64

            raw_body = base64.b64decode(mail["body_b64"])
            cleartext_emails = [
                r["email"] for r in payload["recipients"]
                if r["state"] == policy.STATE_CLEARTEXT_ACKED
            ]
            if certs:
                encrypted = encrypt_message(
                    mail_id=mail_id, snapshot_digest=snapshot["digest"],
                    body=raw_body, recipient_certs=certs,
                    sender_signing_pem=keys["sig_priv_pem"],
                )
            else:
                # 全部收件人均经显式确认明文：无密钥信封，但仍带发件人签名与快照摘要
                from .crypto import canonical, load_ed25519_private

                protected = {
                    "v": 1, "alg": "NONE-EXPLICIT-CLEARTEXT",
                    "enc": "none", "mail_id": mail_id,
                    "snapshot_digest": snapshot["digest"],
                }
                sender_sig = b64e(
                    load_ed25519_private(keys["sig_priv_pem"]).sign(
                        canonical(protected) + raw_body
                    )
                )
                encrypted = {"protected": protected, "iv": None,
                             "ciphertext": None, "sender_sig": sender_sig,
                             "envelopes": []}
            bundle = {
                "mail_id": mail_id,
                "snapshot_digest": snapshot["digest"],
                "encrypted": encrypted,
                "cleartext_recipients": cleartext_emails,
                "cleartext_ack": mail["cleartext_ack"],
            }

            try:
                receipt = self.transport.send(mail_id, bundle)
            except TransportError as exc:
                self.store.cas_mail_status(
                    mail_id, {STATUS_READY, STATUS_SEND_FAILED},
                    {"status": STATUS_SEND_FAILED if exc.transient else STATUS_BLOCKED,
                     "block_reason": None if exc.transient else f"传输永久失败: {exc}",
                     "last_attempt_at": self.store.now(),
                     "last_error": str(exc)},
                )
                self.store.append_audit(EV_SEND_FAILED, mail_id, {
                    "error": str(exc), "transient": exc.transient,
                })
                if not exc.transient:
                    raise
                return self.store.get_mail(mail_id)

            self.store.record_spool(mail_id, receipt, bundle)
            updated = self.store.cas_mail_status(
                mail_id, {STATUS_READY, STATUS_SEND_FAILED},
                {"status": STATUS_SENT, "spool_receipt": receipt,
                 "sent_at": self.store.now(),
                 "last_attempt_at": self.store.now(), "last_error": None},
            )
            if updated is None:
                # 并发状态翻转（例如撤销阻断先发生）：不得投递
                raise StorageError("发送 CAS 失败：邮件状态已被并发改变，已中止投递")
            self.store.append_audit(EV_MAIL_SENT, mail_id, {
                "snapshot_digest": snapshot["digest"],
                "spool_receipt": receipt,
                "encrypted_recipients": [c["serial"] for c in certs],
                "cleartext_recipients": cleartext_emails,
            })
            return updated

    def _revoked_frozen_serials(self, payload: dict) -> list[str]:
        out = []
        for r in payload["recipients"]:
            if r["state"] != policy.STATE_TRUSTED:
                continue
            row = self.store.get_certificate_row(r["cert_serial"])
            if row and row["revoked_at"] is not None:
                out.append(r["cert_serial"])
        return sorted(out)

    # ----------------------------------------------------------- 清单

    def build_manifest(self, mail_id: str, *, verify: bool = True) -> dict:
        mail = self.store.get_mail(mail_id)
        snapshot = self.store.get_snapshot(mail_id)
        recipients = self.store.get_recipients(mail_id)
        spool = self.store.get_spool(mail_id)
        checks: dict[str, Any] = {}
        manifest = {
            "mail_id": mail_id,
            "status": mail["status"],
            "block_reason": mail["block_reason"],
            "sender": mail["sender"],
            "subject": mail["subject"],
            "snapshot_digest": mail["snapshot_digest"],
            "catalog_version": mail["catalog_version"],
            "frozen_at": mail["frozen_at"],
            "sent_at": mail["sent_at"],
            "spool_receipt": mail["spool_receipt"],
            "resubmit_of": mail["resubmit_of"],
            "cleartext_ack": mail["cleartext_ack"],
            "recipients": recipients,
        }
        if verify and snapshot is not None:
            payload = snapshot["payload"]
            checks["snapshot_digest_match"] = (
                policy.snapshot_digest(payload) == snapshot["digest"]
                == mail["snapshot_digest"]
            )
            checks["recipient_count_match"] = (
                len(recipients) == len(payload["recipients"])
            )
            enforced = [r for r in recipients if r["mode"] == "ENFORCE"]
            checks["all_enforced_recipients_encrypted"] = all(
                r["state"] == policy.STATE_TRUSTED for r in enforced
            )
            checks["no_silent_downgrade"] = all(
                r["state"] != policy.STATE_CLEARTEXT_ACKED
                or r["email"] in set(mail["cleartext_ack"])
                for r in recipients
            )
            audit = self.store.verify_audit_chain()
            checks["audit_chain"] = audit

            if spool is not None:
                msg = spool["message"]["encrypted"]
                checks["spool_digest_match"] = (
                    msg["protected"]["snapshot_digest"] == mail["snapshot_digest"]
                )
                checks["spool_receipt_match"] = (
                    spool["receipt"] == mail["spool_receipt"]
                )
                checks["sender_signed"] = bool(msg.get("sender_sig"))
                env_fps = {e["cert_fp"] for e in msg["envelopes"]}
                snap_fps = {
                    r["cert_fp"] for r in payload["recipients"]
                    if r["state"] == policy.STATE_TRUSTED
                }
                checks["envelopes_match_snapshot"] = env_fps == snap_fps
                checks["cleartext_matches_ack"] = (
                    set(spool["message"].get("cleartext_recipients", []))
                    == {r["email"] for r in payload["recipients"]
                        if r["state"] == policy.STATE_CLEARTEXT_ACKED}
                )

                # 发件人签名 + 逐托管收件人用冻结证书对应私钥真实解封
                sender_sig_pub = payload["sender_sig_pub"]
                checks["sender_cert_serial"] = payload["sender_cert_serial"]
                decrypt_results = {}
                import base64

                if env_fps:
                    for r in payload["recipients"]:
                        if r["state"] != policy.STATE_TRUSTED:
                            continue
                        serial = r["cert_serial"]
                        keys = self.store.get_cert_private_key(serial)
                        if keys is None:
                            decrypt_results[r["email"]] = "external-key-not-held"
                            continue
                        try:
                            plain = decrypt_message(
                                msg, recipient_serial=serial,
                                enc_private_pem=keys["enc_priv_pem"],
                                sender_sig_pub_b64=sender_sig_pub,
                            )
                            decrypt_results[r["email"]] = (
                                base64.b64encode(plain).decode() == mail["body_b64"]
                            )
                        except Exception as exc:  # noqa: BLE001
                            decrypt_results[r["email"]] = f"FAILED: {exc}"
                else:
                    # 全显式明文邮件：直接验证发件人对明文的签名
                    from .crypto import canonical, load_ed25519_public_raw

                    try:
                        load_ed25519_public_raw(sender_sig_pub).verify(
                            __import__("base64").b64decode(msg["sender_sig"]),
                            canonical(msg["protected"])
                            + base64.b64decode(mail["body_b64"]),
                        )
                        decrypt_results["cleartext-sender-signature"] = True
                    except Exception as exc:  # noqa: BLE001
                        decrypt_results["cleartext-sender-signature"] = f"FAILED: {exc}"
                checks["decryption_check"] = decrypt_results
                sig_ok = all(
                    v is True or v == "external-key-not-held"
                    for v in decrypt_results.values()
                )
                checks["content_integrity"] = sig_ok

            checks["overall_valid"] = (
                checks["snapshot_digest_match"]
                and checks["recipient_count_match"]
                and checks["all_enforced_recipients_encrypted"]
                and checks["no_silent_downgrade"]
                and checks["audit_chain"]["ok"]
                and (
                    not spool
                    or (checks.get("spool_digest_match")
                        and checks.get("envelopes_match_snapshot")
                        and checks.get("cleartext_matches_ack")
                        and checks.get("sender_signed")
                        and checks.get("content_integrity"))
                )
            )
        manifest["verification"] = checks if verify else {"skipped": True}
        return manifest

