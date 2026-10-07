"""存储层：SQLite（WAL）+ 进程内写锁。

关键不变量：
- 证书轮换以“新版本 + 旧版本 superseded_at”落库，支持按时间点解析；
- 撤销只追加 revoked_at，不删除证书行；
- catalog_version 在每次目录/信任/策略/证书变更时单调递增；
- 快照与收件人冻结行在同一事务写入，写入后不可变；
- 审计日志为 HMAC 防篡改哈希链。
"""
from __future__ import annotations

import hmac
import json
import os
import sqlite3
import threading
import time
from typing import Any, Callable, Optional

from .crypto import (
    canonical,
    certificate_fingerprint,
    generate_identity_keypair,
    sha256_hex,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cas (
    id          TEXT PRIMARY KEY,
    ca_pub_pem  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS certificates (
    serial        TEXT PRIMARY KEY,
    ca_id         TEXT NOT NULL,
    email         TEXT NOT NULL,
    cert_json     TEXT NOT NULL,
    not_before    REAL NOT NULL,
    not_after     REAL NOT NULL,
    superseded_at REAL,
    revoked_at    REAL,
    created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_email ON certificates(email);
CREATE TABLE IF NOT EXISTS directory_entries (
    email      TEXT PRIMARY KEY,
    listed     INTEGER NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_trust (
    domain     TEXT PRIMARY KEY,
    ca_id      TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_policies (
    domain     TEXT PRIMARY KEY,
    mode       TEXT NOT NULL CHECK (mode IN ('ENFORCE','OPPORTUNISTIC')),
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cert_private_keys (
    -- 每个托管证书序列号独立留存私钥；轮换后旧证书仍可用于清单解封验证
    serial       TEXT PRIMARY KEY,
    email        TEXT NOT NULL,
    enc_priv_pem TEXT NOT NULL,
    sig_priv_pem TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS identities (
    -- 身份当前私钥的便捷视图（真实部署中私钥应由 KMS/HSM 持有）
    email         TEXT PRIMARY KEY,
    current_serial TEXT NOT NULL,
    enc_priv_pem  TEXT NOT NULL,
    sig_priv_pem  TEXT NOT NULL,
    created_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS mails (
    id              TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    sender          TEXT NOT NULL,
    subject         TEXT NOT NULL,
    body_b64        TEXT NOT NULL,
    cleartext_ack   TEXT NOT NULL DEFAULT '[]',
    resubmit_of     TEXT,
    status          TEXT NOT NULL,
    block_reason    TEXT,
    snapshot_digest TEXT,
    catalog_version INTEGER,
    created_at      REAL NOT NULL,
    frozen_at       REAL,
    sent_at         REAL,
    last_attempt_at REAL,
    last_error      TEXT,
    spool_receipt   TEXT
);
CREATE TABLE IF NOT EXISTS snapshots (
    mail_id        TEXT PRIMARY KEY,
    payload_json   TEXT NOT NULL,
    digest         TEXT NOT NULL,
    catalog_version INTEGER NOT NULL,
    created_at     REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS mail_recipients (
    mail_id     TEXT NOT NULL,
    email       TEXT NOT NULL,
    mode        TEXT NOT NULL,
    state       TEXT NOT NULL,  -- TRUSTED / CLEARTEXT_ACKED / blocked 原因
    cert_serial TEXT,
    cert_fp     TEXT,
    key_fp      TEXT,
    reason      TEXT,
    PRIMARY KEY (mail_id, email)
);
CREATE TABLE IF NOT EXISTS spool (
    mail_id      TEXT PRIMARY KEY,
    receipt      TEXT NOT NULL,
    message_json TEXT NOT NULL,
    spooled_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    event      TEXT NOT NULL,
    entity     TEXT,
    detail_json TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
"""

# 邮件状态机
STATUS_DRAFT = "DRAFT"
STATUS_READY = "READY"                  # 快照已冻结且全部强制收件人可信
STATUS_BLOCKED = "BLOCKED"             # 密钥缺失/不可信/冻结后撤销，禁止投递
STATUS_SEND_FAILED = "SEND_FAILED"     # 传输层瞬时故障，可用同一快照重试
STATUS_SENT = "SENT"                   # 已投递，终态


class StorageError(Exception):
    pass


class NotFound(StorageError):
    pass


class Store:
    def __init__(self, path: str = ":memory:", clock: Optional[Callable[[], float]] = None):
        self.clock = clock or time.time
        self._wlock = threading.RLock()
        self._mail_locks: dict[str, threading.Lock] = {}
        self._mail_locks_guard = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        if self.get_meta("audit_hmac_secret") is None:
            self.set_meta("audit_hmac_secret", os.urandom(32).hex())
        if self.get_meta("catalog_version") is None:
            self.set_meta("catalog_version", "1")

    # ----------------------------------------------------------- 基础

    def now(self) -> float:
        return self.clock()

    def get_meta(self, key: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._wlock:
            self.conn.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self.conn.commit()

    def bump_catalog_version(self) -> int:
        with self._wlock:
            n = int(self.get_meta("catalog_version")) + 1
            self.set_meta("catalog_version", str(n))
            return n

    def catalog_version(self) -> int:
        return int(self.get_meta("catalog_version"))

    def mail_lock(self, mail_id: str) -> threading.Lock:
        with self._mail_locks_guard:
            lk = self._mail_locks.get(mail_id)
            if lk is None:
                lk = threading.Lock()
                self._mail_locks[mail_id] = lk
            return lk

    # ----------------------------------------------------------- CA

    def create_ca(self, ca_id: str, ca_pub_pem: str, fingerprint: str) -> None:
        with self._wlock:
            try:
                self.conn.execute(
                    "INSERT INTO cas(id,ca_pub_pem,fingerprint,created_at) "
                    "VALUES(?,?,?,?)",
                    (ca_id, ca_pub_pem, fingerprint, self.now()),
                )
                self.conn.commit()
            except sqlite3.IntegrityError as exc:
                raise StorageError(f"CA 已存在: {ca_id}") from exc

    def list_cas(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM cas ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def get_ca_pem(self, ca_id: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT ca_pub_pem FROM cas WHERE id=?", (ca_id,)
        ).fetchone()
        return row["ca_pub_pem"] if row else None

    # ----------------------------------------------------------- 身份/证书/目录

    def install_identity_cert(self, email: str, kp: Any, cert: dict) -> dict:
        """安装由服务层 CA 签发的托管身份（保存私钥）。"""
        return self._install_certificate(email, kp, cert, store_private=True)

    def provision_external_cert(self, cert: dict) -> dict:
        """通讯录更新：导入由受信企业 CA 签发的外部身份证书（无私钥）。"""
        from .crypto import (
            InvalidCertificate,
            load_ed25519_public_pem,
            verify_certificate,
        )

        ca_pem = self.get_ca_pem(cert["ca_id"])
        if ca_pem is None:
            raise NotFound(f"证书的 CA 不受信: {cert['ca_id']}")
        try:
            verify_certificate(cert, load_ed25519_public_pem(ca_pem))
        except InvalidCertificate:
            raise
        email = cert["email"]
        # 外部身份私钥不在网关；用一个只装公钥的壳对象复用安装路径
        kp = _PublicOnly(cert["enc_pub"], cert["sig_pub"])
        return self._install_certificate(email, kp, cert, store_private=False)

    def _install_certificate(self, email, kp, cert, *, store_private: bool) -> dict:
        with self._wlock:
            ts = self.now()
            # 同邮箱旧有效证书标记为被轮换取代
            self.conn.execute(
                "UPDATE certificates SET superseded_at=? "
                "WHERE email=? AND superseded_at IS NULL AND revoked_at IS NULL",
                (ts, email),
            )
            try:
                self.conn.execute(
                    "INSERT INTO certificates(serial,ca_id,email,cert_json,"
                    "not_before,not_after,superseded_at,revoked_at,created_at) "
                    "VALUES(?,?,?,?,?, ?,NULL,NULL,?)",
                    (cert["serial"], cert["ca_id"], email, json.dumps(cert),
                     cert["not_before"], cert["not_after"], ts),
                )
            except sqlite3.IntegrityError as exc:
                raise StorageError(f"证书序列号冲突: {cert['serial']}") from exc
            self.conn.execute(
                "INSERT INTO directory_entries(email,listed,updated_at) "
                "VALUES(?,1,?) ON CONFLICT(email) DO UPDATE SET "
                "listed=1,updated_at=excluded.updated_at",
                (email, ts),
            )
            if store_private:
                self.conn.execute(
                    "INSERT INTO cert_private_keys(serial,email,enc_priv_pem,"
                    "sig_priv_pem) VALUES(?,?,?,?)",
                    (cert["serial"], email, kp.enc_priv_pem, kp.sig_priv_pem),
                )
                self.conn.execute(
                    "INSERT INTO identities(email,current_serial,enc_priv_pem,"
                    "sig_priv_pem,created_at) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(email) DO UPDATE SET "
                    "current_serial=excluded.current_serial,"
                    "enc_priv_pem=excluded.enc_priv_pem,"
                    "sig_priv_pem=excluded.sig_priv_pem",
                    (email, cert["serial"], kp.enc_priv_pem, kp.sig_priv_pem, ts),
                )
            self.bump_catalog_version_locked()
            self.conn.commit()
        return cert

    def revoke_certificate(self, serial: str, at: Optional[float] = None) -> None:
        with self._wlock:
            cur = self.conn.execute(
                "UPDATE certificates SET revoked_at=? WHERE serial=? "
                "AND revoked_at IS NULL",
                (at if at is not None else self.now(), serial),
            )
            if cur.rowcount == 0:
                row = self.conn.execute(
                    "SELECT 1 FROM certificates WHERE serial=?", (serial,)
                ).fetchone()
                if row is None:
                    raise NotFound(f"未知证书: {serial}")
            self.bump_catalog_version_locked()
            self.conn.commit()

    def get_certificate(self, serial: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT cert_json FROM certificates WHERE serial=?", (serial,)
        ).fetchone()
        return json.loads(row["cert_json"]) if row else None

    def get_certificate_row(self, serial: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM certificates WHERE serial=?", (serial,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["cert"] = json.loads(d.pop("cert_json"))
        return d

    def list_certificates(self, email: Optional[str] = None) -> list[dict]:
        if email:
            rows = self.conn.execute(
                "SELECT * FROM certificates WHERE email=? ORDER BY not_before",
                (email,),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM certificates ORDER BY email,not_before"
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["cert"] = json.loads(d.pop("cert_json"))
            out.append(d)
        return out

    def update_directory(self, remove: Optional[list[str]] = None) -> None:
        """通讯录更新：将邮箱标记为下架（密钥历史保留，冻结快照仍可验证）。"""
        remove = remove or []
        with self._wlock:
            ts = self.now()
            for email in remove:
                self.conn.execute(
                    "UPDATE directory_entries SET listed=0,updated_at=? "
                    "WHERE email=?",
                    (ts, email),
                )
            self.bump_catalog_version_locked()
            self.conn.commit()

    def set_domain_trust(self, domain: str, ca_id: str) -> None:
        if self.get_ca_pem(ca_id) is None:
            raise NotFound(f"未知 CA，无法建立域信任: {ca_id}")
        with self._wlock:
            self.conn.execute(
                "INSERT INTO domain_trust(domain,ca_id,updated_at) "
                "VALUES(?,?,?) ON CONFLICT(domain) DO UPDATE SET "
                "ca_id=excluded.ca_id,updated_at=excluded.updated_at",
                (domain.lower(), ca_id, self.now()),
            )
            self.bump_catalog_version_locked()
            self.conn.commit()

    def set_domain_policy(self, domain: str, mode: str) -> None:
        if mode not in ("ENFORCE", "OPPORTUNISTIC"):
            raise StorageError("策略模式必须为 ENFORCE 或 OPPORTUNISTIC")
        with self._wlock:
            self.conn.execute(
                "INSERT INTO domain_policies(domain,mode,updated_at) "
                "VALUES(?,?,?) ON CONFLICT(domain) DO UPDATE SET "
                "mode=excluded.mode,updated_at=excluded.updated_at",
                (domain.lower(), mode, self.now()),
            )
            self.bump_catalog_version_locked()
            self.conn.commit()

    def get_private_keys(self, email: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT current_serial,enc_priv_pem,sig_priv_pem FROM identities WHERE email=?",
            (email,),
        ).fetchone()
        return dict(row) if row else None

    def get_cert_private_key(self, serial: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT email,enc_priv_pem,sig_priv_pem FROM cert_private_keys "
            "WHERE serial=?", (serial,)
        ).fetchone()
        return dict(row) if row else None

    # ----------------------------------------------------------- 目录视图

    def read_catalog(self) -> dict:
        """读取目录一致性视图：CA、域信任、域策略、证书历史、通讯录名单。"""
        cas = {r["id"]: r["ca_pub_pem"] for r in
               self.conn.execute("SELECT id,ca_pub_pem FROM cas").fetchall()}
        trust = {r["domain"]: r["ca_id"] for r in
                 self.conn.execute("SELECT domain,ca_id FROM domain_trust").fetchall()}
        policies = {r["domain"]: r["mode"] for r in
                    self.conn.execute("SELECT domain,mode FROM domain_policies").fetchall()}
        listed = {r["email"] for r in
                  self.conn.execute("SELECT email FROM directory_entries WHERE listed=1").fetchall()}
        certs = []
        for r in self.conn.execute("SELECT * FROM certificates").fetchall():
            d = dict(r)
            d["cert"] = json.loads(d.pop("cert_json"))
            certs.append(d)
        return {
            "catalog_version": self.catalog_version(),
            "cas": cas,
            "trust": trust,
            "policies": policies,
            "listed": listed,
            "certificates": certs,
        }

    # ----------------------------------------------------------- 邮件/快照

    def create_mail(
        self,
        *,
        mail_id: str,
        idempotency_key: Optional[str],
        sender: str,
        subject: str,
        body_b64: str,
        cleartext_ack: list[str],
        resubmit_of: Optional[str],
    ) -> dict:
        with self._wlock:
            try:
                self.conn.execute(
                    "INSERT INTO mails(id,idempotency_key,sender,subject,body_b64,"
                    "cleartext_ack,resubmit_of,status,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (mail_id, idempotency_key, sender, subject, body_b64,
                     json.dumps(cleartext_ack), resubmit_of, STATUS_DRAFT, self.now()),
                )
                self.conn.commit()
            except sqlite3.IntegrityError as exc:
                raise StorageError("幂等键冲突或邮件 ID 已存在") from exc
        return self.get_mail(mail_id)

    def get_mail(self, mail_id: str) -> dict:
        row = self.conn.execute(
            "SELECT * FROM mails WHERE id=?", (mail_id,)
        ).fetchone()
        if not row:
            raise NotFound(f"未知邮件: {mail_id}")
        d = dict(row)
        d["cleartext_ack"] = json.loads(d["cleartext_ack"])
        return d

    def list_mails(self, limit: int = 100) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM mails ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["cleartext_ack"] = json.loads(d.pop("cleartext_ack"))
            out.append(d)
        return out

    def find_by_idempotency_key(self, key: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM mails WHERE idempotency_key=?", (key,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["cleartext_ack"] = json.loads(d["cleartext_ack"])
        return d

    def freeze_snapshot(
        self,
        *,
        mail_id: str,
        payload: dict,
        digest: str,
        recipients: list[dict],
        status: str,
        block_reason: Optional[str],
    ) -> None:
        """同一事务内写入：快照载荷 + 摘要 + 冻结收件人集合 + 邮件状态。"""
        with self._wlock:
            ts = self.now()
            self.conn.execute(
                "INSERT INTO snapshots(mail_id,payload_json,digest,"
                "catalog_version,created_at) VALUES(?,?,?,?,?)",
                (mail_id, json.dumps(payload, ensure_ascii=False), digest,
                 payload["catalog_version"], ts),
            )
            for r in recipients:
                self.conn.execute(
                    "INSERT INTO mail_recipients(mail_id,email,mode,state,"
                    "cert_serial,cert_fp,key_fp,reason) VALUES(?,?,?,?,?,?,?,?)",
                    (mail_id, r["email"], r["mode"], r["state"],
                     r.get("cert_serial"), r.get("cert_fp"),
                     r.get("key_fp"), r.get("reason")),
                )
            self.conn.execute(
                "UPDATE mails SET status=?,block_reason=?,snapshot_digest=?,"
                "catalog_version=?,frozen_at=? WHERE id=?",
                (status, block_reason, digest, payload["catalog_version"], ts, mail_id),
            )
            self.conn.commit()

    def get_snapshot(self, mail_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM snapshots WHERE mail_id=?", (mail_id,)
        ).fetchall()
        if not row:
            return None
        r = dict(row[0])
        r["payload"] = json.loads(r.pop("payload_json"))
        return r

    def get_recipients(self, mail_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM mail_recipients WHERE mail_id=? ORDER BY email",
            (mail_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def cas_mail_status(
        self, mail_id: str, expected: set[str], updates: dict
    ) -> Optional[dict]:
        """状态比较-交换，防止并发重复发送。返回更新后邮件，状态不符返回 None。"""
        sets, vals = [], []
        for k, v in updates.items():
            sets.append(f"{k}=?")
            vals.append(json.dumps(v) if k == "cleartext_ack" else v)
        vals.append(mail_id)
        with self._wlock:
            row = self.conn.execute(
                "SELECT status FROM mails WHERE id=?", (mail_id,)
            ).fetchone()
            if not row or row["status"] not in expected:
                return None
            self.conn.execute(
                f"UPDATE mails SET {', '.join(sets)} WHERE id=?", vals
            )
            self.conn.commit()
        return self.get_mail(mail_id)

    def record_spool(self, mail_id: str, receipt: str, message: dict) -> None:
        with self._wlock:
            self.conn.execute(
                "INSERT OR IGNORE INTO spool(mail_id,receipt,message_json,spooled_at) "
                "VALUES(?,?,?,?)",
                (mail_id, receipt, json.dumps(message, ensure_ascii=False), self.now()),
            )
            self.conn.commit()

    def get_spool(self, mail_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM spool WHERE mail_id=?", (mail_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["message"] = json.loads(d.pop("message_json"))
        return d

    # ----------------------------------------------------------- 审计链

    def append_audit(self, event: str, entity: Optional[str], detail: dict) -> dict:
        with self._wlock:
            ts = self.now()
            prev = self.conn.execute(
                "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = prev["entry_hash"] if prev else "GENESIS"
            body = canonical({
                "ts": round(ts, 6), "event": event,
                "entity": entity, "detail": detail,
            })
            secret = self.get_meta("audit_hmac_secret")
            entry_hash = hmac.new(
                bytes.fromhex(secret), prev_hash.encode() + body, "sha256"
            ).hexdigest()
            cur = self.conn.execute(
                "INSERT INTO audit_log(ts,event,entity,detail_json,entry_hash) "
                "VALUES(?,?,?,?,?)",
                (ts, event, entity, json.dumps(detail, ensure_ascii=False), entry_hash),
            )
            self.conn.commit()
            return {"id": cur.lastrowid, "ts": ts, "event": event,
                    "entity": entity, "detail": detail, "entry_hash": entry_hash,
                    "prev_hash": prev_hash}

    def verify_audit_chain(self) -> dict:
        secret = self.get_meta("audit_hmac_secret")
        rows = self.conn.execute(
            "SELECT * FROM audit_log ORDER BY id").fetchall()
        prev_hash = "GENESIS"
        for r in rows:
            body = canonical({
                "ts": round(r["ts"], 6), "event": r["event"],
                "entity": r["entity"], "detail": json.loads(r["detail_json"]),
            })
            expect = hmac.new(
                bytes.fromhex(secret), prev_hash.encode() + body, "sha256"
            ).hexdigest()
            if not hmac.compare_digest(expect, r["entry_hash"]):
                return {"ok": False, "broken_at": r["id"], "entries": len(rows)}
            prev_hash = r["entry_hash"]
        return {"ok": True, "entries": len(rows),
                "head": prev_hash if rows else "GENESIS"}

    def list_audit(self, limit: int = 100) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id,ts,event,entity,detail_json,entry_hash FROM audit_log "
            "ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [{"id": r["id"], "ts": r["ts"], "event": r["event"],
                 "entity": r["entity"], "detail": json.loads(r["detail_json"]),
                 "entry_hash": r["entry_hash"]} for r in rows]

    def bump_catalog_version_locked(self) -> None:
        n = int(self.get_meta("catalog_version")) + 1
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES('catalog_version',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(n),),
        )

    def close(self) -> None:
        self.conn.close()


class _PublicOnly:
    """外部证书的壳对象：只有公钥字段，私钥字段为空。"""

    def __init__(self, enc_pub: str, sig_pub: str):
        self.enc_pub = enc_pub
        self.sig_pub = sig_pub
        self.enc_priv_pem = ""
        self.sig_priv_pem = ""
