"""策略引擎：按收件人域、身份与时间点解析证书并做出投递判定。

安全语义：
- ENFORCE（强制加密）：收件人必须在“该时间点”拥有受信 CA 签发、未过期、
  未撤销、未被轮换取代且仍在通讯录中的密钥，否则整体禁止投递；
- OPPORTUNISTIC（机会加密）：有可信密钥时必须加密（即使有明文授权也不用明文），
  仅在无可用密钥且发件人逐地址显式确认（ack）时才允许明文，否则同样禁止；
  系统不存在“密钥缺失时自动明文”的路径。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .crypto import (
    InvalidCertificate,
    canonical,
    certificate_fingerprint,
    key_fingerprint,
    load_ed25519_public_pem,
    sha256_hex,
    verify_certificate,
)

DEFAULT_MODE = "ENFORCE"
STATE_TRUSTED = "TRUSTED"
STATE_CLEARTEXT_ACKED = "CLEARTEXT_ACKED"

# 阻断类状态
STATE_MISSING_KEY = "MISSING_KEY"
STATE_UNLISTED = "UNLISTED"
STATE_EXPIRED = "EXPIRED"
STATE_NOT_YET_VALID = "NOT_YET_VALID"
STATE_REVOKED = "REVOKED"
STATE_UNTRUSTED_CA = "UNTRUSTED_CA"
STATE_NO_DOMAIN_TRUST = "NO_DOMAIN_TRUST"
STATE_BAD_SIGNATURE = "BAD_SIGNATURE"
STATE_MISSING_ACK = "MISSING_ACK"

BLOCK_STATES = {
    STATE_MISSING_KEY, STATE_UNLISTED, STATE_EXPIRED, STATE_NOT_YET_VALID,
    STATE_REVOKED, STATE_UNTRUSTED_CA, STATE_NO_DOMAIN_TRUST,
    STATE_BAD_SIGNATURE, STATE_MISSING_ACK,
}


@dataclass
class Resolution:
    email: str
    domain: str
    mode: str
    state: str = ""
    reason: Optional[str] = None
    ca_id: Optional[str] = None
    cert_serial: Optional[str] = None
    cert_fp: Optional[str] = None
    key_fp: Optional[str] = None
    not_before: Optional[float] = None
    not_after: Optional[float] = None
    cert: Optional[dict] = field(default=None, repr=False)

    def is_trusted(self) -> bool:
        return self.state == STATE_TRUSTED

    def to_snapshot(self) -> dict:
        return {
            "email": self.email,
            "domain": self.domain,
            "mode": self.mode,
            "state": self.state,
            "reason": self.reason,
            "ca_id": self.ca_id,
            "cert_serial": self.cert_serial,
            "cert_fp": self.cert_fp,
            "key_fp": self.key_fp,
            "not_before": self.not_before,
            "not_after": self.not_after,
        }


def domain_of(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower() if "@" in email else email.lower()


def mode_for(domain: str, catalog: dict, override: Optional[str]) -> str:
    if override:
        if override not in ("ENFORCE", "OPPORTUNISTIC"):
            raise ValueError(f"非法模式覆盖: {override}")
        return override
    return catalog["policies"].get(domain, DEFAULT_MODE)


def _select_cert_row(email: str, at: float, catalog: dict) -> Optional[dict]:
    """时间点解析：在 at 时刻有效的最新证书（未撤销/未过期/未被取代）。"""
    candidates = []
    for row in catalog["certificates"]:
        if row["email"] != email:
            continue
        if row["not_before"] > at:
            continue
        if row["not_after"] <= at:
            continue
        if row["revoked_at"] is not None and row["revoked_at"] <= at:
            continue
        if row["superseded_at"] is not None and row["superseded_at"] <= at:
            continue
        candidates.append(row)
    if not candidates:
        return None
    return max(candidates, key=lambda r: (r["not_before"], r["serial"]))


def resolve_recipient(
    email: str,
    catalog: dict,
    at: float,
    *,
    mode_override: Optional[str] = None,
    acked: bool = False,
) -> Resolution:
    email = email.strip().lower()
    domain = domain_of(email)
    mode = mode_for(domain, catalog, mode_override)
    res = Resolution(email=email, domain=domain, mode=mode)

    # 1) 通讯录必须列出该身份
    if email not in catalog["listed"]:
        res.state = STATE_UNLISTED
        res.reason = "收件人不在企业通讯录中（可能已下架）"
        return _apply_policy(res, acked)

    # 2) 该域必须配置信任锚
    trusted_ca = catalog["trust"].get(domain)
    if trusted_ca is None:
        res.state = STATE_NO_DOMAIN_TRUST
        res.reason = f"域 {domain} 未配置受信证书颁发机构"
        return _apply_policy(res, acked)

    # 3) 时间点证书选择
    row = _select_cert_row(email, at, catalog)
    if row is None:
        # 分类阻断原因（该身份可能有多代证书）
        rows_for_email = [r for r in catalog["certificates"]
                          if r["email"] == email]
        unexpired = [r for r in rows_for_email if r["not_before"] <= at < r["not_after"]]
        active = [r for r in unexpired
                  if (r["superseded_at"] is None or r["superseded_at"] > at)]
        revoked_active = [r for r in active if r["revoked_at"] is not None
                          and r["revoked_at"] <= at]
        if revoked_active:
            res.state = STATE_REVOKED
            res.reason = "该时间点唯一有效的证书已被撤销"
        elif not rows_for_email:
            res.state = STATE_MISSING_KEY
            res.reason = "通讯录中没有该收件人的加密证书"
        else:
            latest = max(rows_for_email, key=lambda r: r["not_before"])
            if latest["not_before"] > at:
                res.state = STATE_NOT_YET_VALID
                res.reason = "证书尚未生效"
            elif latest["not_after"] <= at:
                res.state = STATE_EXPIRED
                res.reason = f"证书已于 {latest['not_after']} 过期"
            else:
                res.state = STATE_MISSING_KEY
                res.reason = "通讯录中没有该收件人在该时间点可用的加密证书（旧证书均已被轮换取代）"
        return _apply_policy(res, acked)

    cert = row["cert"]
    res.ca_id = cert["ca_id"]
    res.cert_serial = cert["serial"]
    res.cert_fp = certificate_fingerprint(cert)
    res.key_fp = key_fingerprint(cert["enc_pub"])
    res.not_before = cert["not_before"]
    res.not_after = cert["not_after"]

    # 4) 证书链必须由该域受信 CA 签发且签名有效
    if cert["ca_id"] != trusted_ca:
        res.state = STATE_UNTRUSTED_CA
        res.reason = (
            f"证书由 CA {cert['ca_id']} 签发，但域 {domain} 只信任 {trusted_ca}"
        )
        return _apply_policy(res, acked)
    ca_pem = catalog["cas"].get(trusted_ca)
    if ca_pem is None:
        res.state = STATE_UNTRUSTED_CA
        res.reason = f"受信 CA {trusted_ca} 的公钥缺失"
        return _apply_policy(res, acked)
    try:
        verify_certificate(cert, load_ed25519_public_pem(ca_pem))
    except InvalidCertificate as exc:
        res.state = STATE_BAD_SIGNATURE
        res.reason = str(exc)
        return _apply_policy(res, acked)

    res.state = STATE_TRUSTED
    res.cert = cert
    return res


def _apply_policy(res: Resolution, acked: bool) -> Resolution:
    """把密钥解析结果映射到强制/机会策略的最终决定。"""
    if res.state == STATE_TRUSTED:
        return res  # 有可信密钥：一律加密，明文授权无效，绝不降级
    if res.mode == "ENFORCE":
        return res  # 强制域：任何非可信状态都阻断
    # OPPORTUNISTIC：密钥确实不可用时，必须有逐地址显式确认才能明文
    if acked:
        res.reason = (res.reason or "") + "（发件人已显式确认明文投递）"
        res.state = STATE_CLEARTEXT_ACKED
        return res
    res.state = STATE_MISSING_ACK
    res.reason = (
        f"机会加密域缺少可信密钥（{res.reason}），"
        "且发件人未在 cleartext_ack 中逐地址显式确认；禁止静默降级"
    )
    return res


def evaluate(
    recipients: list[dict], catalog: dict, at: float
) -> dict:
    """对整封邮件的收件人集合做一次完整解析。

    recipients: [{"email": ..., "mode": 可选覆盖, "cleartext_ack": bool}]
    """
    ack_set = {
        r["email"].strip().lower()
        for r in recipients if r.get("cleartext_ack")
    }
    resolutions = [
        resolve_recipient(
            r["email"], catalog, at,
            mode_override=r.get("mode"),
            acked=r["email"].strip().lower() in ack_set,
        )
        for r in recipients
    ]
    blocked = [r for r in resolutions if r.state in BLOCK_STATES]
    trusted = [r for r in resolutions if r.is_trusted()]
    cleartext = [r for r in resolutions if r.state == STATE_CLEARTEXT_ACKED]
    return {
        "at": at,
        "catalog_version": catalog["catalog_version"],
        "resolutions": resolutions,
        "trusted": trusted,
        "cleartext": cleartext,
        "blocked": blocked,
        "allowed": not blocked,
    }


def build_snapshot_payload(
    *,
    mail_id: str,
    sender: str,
    sender_cert_serial: str,
    sender_sig_pub: str,
    subject: str,
    body_b64: str,
    decision: dict,
) -> dict:
    """构造冻结快照载荷：收件人集合 + 证书摘要 + 策略依据，全部不可变。"""
    return {
        "v": 1,
        "mail_id": mail_id,
        "sender": sender.strip().lower(),
        "sender_cert_serial": sender_cert_serial,
        "sender_sig_pub": sender_sig_pub,
        "subject": subject,
        "body_sha256": sha256_hex(body_b64.encode("ascii")),
        "frozen_at": round(decision["at"], 6),
        "catalog_version": decision["catalog_version"],
        "default_mode": DEFAULT_MODE,
        "recipients": [r.to_snapshot() for r in decision["resolutions"]],
    }


def snapshot_digest(payload: dict) -> str:
    """完整密钥快照摘要（64 位十六进制 SHA-256）。"""
    return sha256_hex(canonical(payload))


def trusted_certs_from_snapshot(payload: dict, catalog: dict) -> list[dict]:
    """从冻结快照取出 TRUSTED 收件人的证书对象（按序列号索引）。"""
    serials = {
        r["cert_serial"] for r in payload["recipients"]
        if r["state"] == STATE_TRUSTED
    }
    by_serial = {c["serial"]: c for c in
                 (row["cert"] for row in catalog["certificates"])}
    missing = serials - set(by_serial)
    if missing:
        # 证书历史记录即使撤销/删除视图异常，也必须可从历史复原；
        # 生产中证书行不可删除，这里属于数据完整性故障，fail-closed。
        raise RuntimeError(f"冻结快照引用的证书无法复原: {sorted(missing)}")
    return [by_serial[s] for s in sorted(serials)]


def verify_snapshot_recipients(payload: dict, decision: dict) -> list[str]:
    """校验决策结果与待冻结载荷一致，返回不一致项（空列表=一致）。"""
    errors = []
    fresh = {r.email: r for r in decision["resolutions"]}
    frozen = {r["email"]: r for r in payload["recipients"]}
    if set(fresh) != set(frozen):
        errors.append("冻结收件人集合与解析结果不一致")
    for email, res in fresh.items():
        f = frozen.get(email)
        if f and (f["cert_fp"], f["state"], f["mode"]) != (
            res.cert_fp, res.state, res.mode
        ):
            errors.append(f"{email}: 冻结证书摘要/状态与解析不一致")
    return errors
