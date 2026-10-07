"""密码学原语封装。

全部基于 Python 标准库 + openssl 3.0 CLI（环境无 pip/第三方库）：

* 信封密钥 CEK：32 字节随机数，切分为 AES-256 key(32) 与 HMAC-SHA256 key(32)
* 邮件正文：AES-256-CBC + HMAC-SHA256（Encrypt-then-MAC，认证加密）
* 逐收件人：RSA-2048-OAEP(SHA-256) 封装 CEK
* 投递清单：RSA-PSS(SHA-256) 由网关身份密钥签名，任何人可用网关公钥验证

注意：本模块所有 openssl 调用均走临时文件，避免命令行传参泄露敏感材料。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import tempfile
import uuid
from base64 import b64decode, b64encode

OPENSSL = os.environ.get("OPENSSL_BIN", "openssl")


class CryptoError(Exception):
    """密码学操作失败（解密失败、MAC 校验失败等）。"""


def _run(args: list[str], stdin: bytes | None = None) -> bytes:
    proc = subprocess.run(
        args,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise CryptoError(
            f"openssl {' '.join(str(a) for a in args[:2])} 失败: "
            f"{proc.stderr.decode(errors='replace')[:300]}"
        )
    return proc.stdout


def b64e(data: bytes) -> str:
    return b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return b64decode(text.encode("ascii"), validate=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def random_hex(nbytes: int = 16) -> str:
    return os.urandom(nbytes).hex()


def new_cek() -> str:
    """生成新的 64 字节信封密钥，返回 hex。"""
    return os.urandom(64).hex()


# ---------------------------------------------------------------------------
# RSA 密钥与证书（通讯录中的收件人身份证书，网关只持有公钥）
# ---------------------------------------------------------------------------

def gen_rsa_key(bits: int = 2048) -> str:
    """生成 RSA 私钥 PEM。"""
    return _run([OPENSSL, "genpkey", "-algorithm", "RSA",
                 "-pkeyopt", f"rsa_keygen_bits:{bits}"]).decode()


def public_pem(private_pem: str) -> str:
    """从私钥 PEM 导出公钥 PEM。"""
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(private_pem)
        path = f.name
    try:
        return _run([OPENSSL, "pkey", "-in", path, "-pubout"]).decode()
    finally:
        os.unlink(path)


def gen_self_signed_cert(private_pem: str, cn: str, days: int = 365,
                         extra_emails: list[str] | None = None) -> str:
    """用私钥生成自签名 X.509 证书 PEM（企业内部 PKI/信任锚模型）。"""
    alt = ",".join([f"email:{cn}"] + [f"email:{e}" for e in (extra_emails or [])])
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as kf:
        kf.write(private_pem)
        kpath = kf.name
    try:
        return _run([
            OPENSSL, "req", "-new", "-x509", "-key", kpath,
            "-subj", f"/CN={cn}",
            "-days", str(days),
            "-addext", f"subjectAltName={alt}",
            "-sha256",
        ]).decode()
    finally:
        os.unlink(kpath)


def cert_fingerprint(cert_pem: str) -> str:
    """证书 DER 的 SHA-256 指纹（大写冒号分隔），作为密钥摘要。"""
    out = _run([OPENSSL, "x509", "-in", _pem_tmp(cert_pem),
                "-noout", "-fingerprint", "-sha256"]).decode()
    fp = out.split("=", 1)[1].strip()
    return fp.lower()


def cert_public_key(cert_pem: str) -> str:
    """从证书 PEM 提取公钥 PEM（用于加密，绝不触达私钥库）。"""
    return _run([OPENSSL, "x509", "-in", _pem_tmp(cert_pem),
                 "-pubkey", "-noout"]).decode()


def cert_times(cert_pem: str) -> tuple[str, str]:
    """返回证书 (notBefore, notAfter)，openssl 原生时间字符串。"""
    path = _pem_tmp(cert_pem)
    try:
        nb = _run([OPENSSL, "x509", "-in", path, "-noout",
                   "-startdate"]).decode().split("=", 1)[1].strip()
        na = _run([OPENSSL, "x509", "-in", path, "-noout",
                   "-enddate"]).decode().split("=", 1)[1].strip()
        return nb, na
    finally:
        os.unlink(path)


def cert_cn(cert_pem: str) -> str:
    out = _run([OPENSSL, "x509", "-in", _pem_tmp(cert_pem),
                "-noout", "-subject"]).decode().strip()
    # subject=CN = alice@corp.example
    return out.split("=", 1)[-1].strip()


def _pem_tmp(pem: str) -> str:
    f = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    f.write(pem)
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# 正文加密：AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
# ---------------------------------------------------------------------------

def encrypt_body(cek_hex: str, plaintext: bytes, aad: bytes = b"") -> dict:
    """AES-256-CBC 加密后对 IV||密文做 HMAC-SHA256。

    aad 绑定信封上下文（如清单头），防止密文被搬移到其他邮件。
    """
    key_hex, mac_hex = cek_hex[:64], cek_hex[64:]
    iv = os.urandom(16)
    ct = _run([
        OPENSSL, "enc", "-aes-256-cbc",
        "-K", key_hex, "-iv", iv.hex(),
    ], stdin=plaintext)
    blob = iv + ct
    mac = hmac.new(bytes.fromhex(mac_hex), aad + blob, hashlib.sha256).digest()
    return {"iv": b64e(iv), "ciphertext": b64e(ct), "mac": b64e(mac)}


def decrypt_body(cek_hex: str, box: dict, aad: bytes = b"") -> bytes:
    key_hex, mac_hex = cek_hex[:64], cek_hex[64:]
    iv, ct = b64d(box["iv"]), b64d(box["ciphertext"])
    blob = iv + ct
    expected = b64d(box["mac"])
    actual = hmac.new(bytes.fromhex(mac_hex), aad + blob,
                      hashlib.sha256).digest()
    if not hmac.compare_digest(expected, actual):
        raise CryptoError("HMAC 校验失败：邮件正文可能被篡改")
    return _run([
        OPENSSL, "enc", "-d", "-aes-256-cbc",
        "-K", key_hex, "-iv", iv.hex(),
    ], stdin=ct)


# ---------------------------------------------------------------------------
# RSA-OAEP 密钥封装
# ---------------------------------------------------------------------------

def rsa_wrap(recipient_cert_pem: str, cek_hex: str) -> str:
    """用收件人证书公钥 RSA-OAEP(SHA-256) 封装 CEK，返回 base64。"""
    pub = cert_public_key(recipient_cert_pem)
    ppath = _pem_tmp(pub)
    kpath = _pem_bytes(bytes.fromhex(cek_hex))
    opath = tempfile.mktemp()
    try:
        _run([
            OPENSSL, "pkeyutl", "-encrypt",
            "-pubin", "-inkey", ppath,
            "-in", kpath, "-out", opath,
            "-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", "rsa_oaep_md:sha256",
            "-pkeyopt", "rsa_mgf1_md:sha256",
        ])
        with open(opath, "rb") as f:
            return b64e(f.read())
    finally:
        for p in (ppath, kpath, opath):
            if os.path.exists(p):
                os.unlink(p)


def rsa_unwrap(private_pem: str, wrapped_b64: str) -> str:
    """收件人侧解密（演示/测试用）：返回 CEK hex。"""
    kpath = _pem_tmp(private_pem)
    ipath = _pem_bytes(b64d(wrapped_b64))
    opath = tempfile.mktemp()
    try:
        _run([
            OPENSSL, "pkeyutl", "-decrypt",
            "-inkey", kpath,
            "-in", ipath, "-out", opath,
            "-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", "rsa_oaep_md:sha256",
            "-pkeyopt", "rsa_mgf1_md:sha256",
        ])
        with open(opath, "rb") as f:
            return f.read().hex()
    finally:
        for p in (kpath, ipath, opath):
            if os.path.exists(p):
                os.unlink(p)


def _pem_bytes(data: bytes) -> str:
    f = tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False)
    f.write(data)
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# 网关身份签名：RSA-PSS over SHA-256
# ---------------------------------------------------------------------------

def pss_sign(private_pem: str, message: bytes) -> str:
    kpath = _pem_tmp(private_pem)
    mpath = _pem_bytes(message)
    try:
        out = _run([
            OPENSSL, "dgst", "-sha256", "-sign", kpath,
            "-sigopt", "rsa_padding_mode:pss",
            "-sigopt", "rsa_pss_saltlen:32",
            mpath,
        ])
        return b64e(out)
    finally:
        os.unlink(kpath)
        os.unlink(mpath)


def pss_verify(public_pem_text: str, message: bytes, signature_b64: str) -> bool:
    ppath = _pem_tmp(public_pem_text)
    mpath = _pem_bytes(message)
    spath = _pem_bytes(b64d(signature_b64))
    try:
        proc = subprocess.run([
            OPENSSL, "dgst", "-sha256", "-verify", ppath,
            "-signature", spath,
            "-sigopt", "rsa_padding_mode:pss",
            "-sigopt", "rsa_pss_saltlen:32",
            mpath,
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return proc.returncode == 0 and b"OK" in proc.stdout
    finally:
        for p in (ppath, mpath, spath):
            os.unlink(p)


def envelope_id() -> str:
    return "env_" + uuid.uuid4().hex
