"""加密原语层。

- 企业根 CA 使用 Ed25519，证书为 CA 签名的紧凑 JSON 对象；
- 收件人加密公钥为 X25519；
- 邮件采用混合加密：随机 body_key + AES-256-GCM 加密正文，
  body_key 经 X25519 ECDH/HKDF 派生 KEK 后按收件人逐一封装；
- 发件人用自己证书中的 Ed25519 签名公钥对受保护头与密文签名。

全部为真实密码学操作（cryptography 库），非模拟。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

WRAP_INFO = b"e2ee-gateway-wrap-v1"
PROTECTED_ALG = "ECDH-X25519-HKDF-SHA256/AES-256-GCM"
PROTECTED_ENC = "A256GCM"
CERT_VERSION = 1
MESSAGE_VERSION = 1


# ---------------------------------------------------------------- 编码工具

def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def canonical(obj: Any) -> bytes:
    """确定性规范化 JSON：排序键、无空白，作为签名/摘要的唯一字节序列。"""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------- 密钥对

@dataclass
class IdentityKeyPair:
    """一个身份的两把公钥及对应私钥（PEM）。"""

    enc_pub: str          # X25519 公钥，base64
    sig_pub: str          # Ed25519 公钥，base64
    enc_priv_pem: str
    sig_priv_pem: str


def generate_identity_keypair() -> IdentityKeyPair:
    enc = X25519PrivateKey.generate()
    sig = Ed25519PrivateKey.generate()
    return IdentityKeyPair(
        enc_pub=b64e(
            enc.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ),
        sig_pub=b64e(
            sig.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ),
        enc_priv_pem=enc.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode(),
        sig_priv_pem=sig.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode(),
    )


def load_ed25519_private(pem: str) -> Ed25519PrivateKey:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    return load_pem_private_key(pem.encode(), password=None)


def load_ed25519_public_pem(pem: str) -> Ed25519PublicKey:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    return load_pem_public_key(pem.encode())


def load_ed25519_public_raw(raw_b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(b64d(raw_b64))


def load_x25519_private_pem(pem: str) -> X25519PrivateKey:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    return load_pem_private_key(pem.encode(), password=None)


def ed25519_public_pem(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    pub = key if isinstance(key, Ed25519PublicKey) else key.public_key()
    return pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def ed25519_raw_pub(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


# ---------------------------------------------------------------- 企业 CA

class CertificateAuthority:
    """企业根 CA（Ed25519 签发）。"""

    def __init__(self, ca_id: str, signing_key: Ed25519PrivateKey):
        self.ca_id = ca_id
        self.key = signing_key

    @classmethod
    def generate(cls, ca_id: str) -> "CertificateAuthority":
        return cls(ca_id, Ed25519PrivateKey.generate())

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.key.public_key()

    def public_pem(self) -> str:
        return ed25519_public_pem(self.key)

    def fingerprint(self) -> str:
        return sha256_hex(ed25519_raw_pub(self.public_key))

    def issue_certificate(
        self,
        serial: str,
        email: str,
        identity: IdentityKeyPair,
        not_before: float,
        not_after: float,
    ) -> dict:
        tbs = {
            "v": CERT_VERSION,
            "ca_id": self.ca_id,
            "serial": serial,
            "email": email,
            "enc_pub": identity.enc_pub,
            "sig_pub": identity.sig_pub,
            "not_before": round(not_before, 6),
            "not_after": round(not_after, 6),
        }
        signature = self.key.sign(canonical(tbs))
        cert = dict(tbs)
        cert["sig"] = b64e(signature)
        return cert


def cert_tbs(cert: dict) -> dict:
    return {k: cert[k] for k in ("v", "ca_id", "serial", "email", "enc_pub",
                                 "sig_pub", "not_before", "not_after")}


def certificate_fingerprint(cert: dict) -> str:
    """证书摘要：对完整证书对象（含签名）做 SHA-256。"""
    return sha256_hex(canonical(cert))


def key_fingerprint(pub_b64: str) -> str:
    return sha256_hex(b64d(pub_b64))


def verify_certificate(cert: dict, ca_public_key: Ed25519PublicKey) -> None:
    """校验证书签名与结构；任何失败都抛 InvalidCertificate。"""
    required = {"v", "ca_id", "serial", "email", "enc_pub", "sig_pub",
                "not_before", "not_after", "sig"}
    missing = required - set(cert)
    if missing:
        raise InvalidCertificate(f"证书字段缺失: {sorted(missing)}")
    try:
        ca_public_key.verify(b64d(cert["sig"]), canonical(cert_tbs(cert)))
    except Exception as exc:  # noqa: BLE001
        raise InvalidCertificate(f"证书签名无效: {exc}") from exc


class InvalidCertificate(Exception):
    pass


# ---------------------------------------------------------------- 邮件封装

def encrypt_message(
    *,
    mail_id: str,
    snapshot_digest: str,
    body: bytes,
    recipient_certs: list[dict],
    sender_signing_pem: str,
) -> dict:
    """生成端到端加密邮件：一个密文正文 + 每收件人一个密钥封装。"""
    if not recipient_certs:
        raise ValueError("至少需要一个加密收件人")

    protected = {
        "v": MESSAGE_VERSION,
        "alg": PROTECTED_ALG,
        "enc": PROTECTED_ENC,
        "mail_id": mail_id,
        "snapshot_digest": snapshot_digest,
    }
    aad = canonical(protected)

    body_key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(body_key).encrypt(nonce, body, aad)

    ephemeral = X25519PrivateKey.generate()
    eph_pub = b64e(
        ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    salt = bytes.fromhex(snapshot_digest)

    envelopes = []
    for cert in sorted(recipient_certs, key=lambda c: c["serial"]):
        peer = X25519PublicKey.from_public_bytes(b64d(cert["enc_pub"]))
        shared = ephemeral.exchange(peer)
        kek = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=WRAP_INFO,
        ).derive(shared)
        wrap_nonce = os.urandom(12)
        wrapped = AESGCM(kek).encrypt(
            wrap_nonce, body_key, cert["serial"].encode("utf-8")
        )
        envelopes.append({
            "serial": cert["serial"],
            "cert_fp": certificate_fingerprint(cert),
            "eph_pub": eph_pub,
            "wrap_iv": b64e(wrap_nonce),
            "wrapped_key": b64e(wrapped),
        })

    sender_key = load_ed25519_private(sender_signing_pem)
    sender_sig = b64e(sender_key.sign(aad + ciphertext))

    return {
        "protected": protected,
        "iv": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "sender_sig": sender_sig,
        "envelopes": envelopes,
    }


def decrypt_message(
    message: dict,
    *,
    recipient_serial: str,
    enc_private_pem: str,
    sender_sig_pub_b64: str,
) -> bytes:
    """收件人侧解封：校验发件人签名并用自己的 X25519 私钥解密正文。"""
    protected = message["protected"]
    aad = canonical(protected)
    ciphertext = b64d(message["ciphertext"])

    envelope = next(
        (e for e in message["envelopes"] if e["serial"] == recipient_serial),
        None,
    )
    if envelope is None:
        raise DecryptionError("密文中没有该收件人的密钥封装")

    salt = bytes.fromhex(protected["snapshot_digest"])
    priv = load_x25519_private_pem(enc_private_pem)
    eph_pub = X25519PublicKey.from_public_bytes(b64d(envelope["eph_pub"]))
    shared = priv.exchange(eph_pub)
    kek = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=WRAP_INFO
    ).derive(shared)
    body_key = AESGCM(kek).decrypt(
        b64d(envelope["wrap_iv"]),
        b64d(envelope["wrapped_key"]),
        recipient_serial.encode("utf-8"),
    )
    body = AESGCM(body_key).decrypt(b64d(message["iv"]), ciphertext, aad)

    # 发件人签名必须验证通过
    load_ed25519_public_raw(sender_sig_pub_b64).verify(
        b64d(message["sender_sig"]), aad + ciphertext
    )
    return body


class DecryptionError(Exception):
    pass
