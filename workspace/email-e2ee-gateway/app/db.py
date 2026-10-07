"""SQLite 存储层、逻辑时钟与网关身份引导。

并发模型：
* WAL + busy_timeout=5000，写事务统一 BEGIN IMMEDIATE，
  保证"预检冻结 / 发送占用 / 重试幂等"在多线程下串行化。
* 密钥快照行的状态机 (prepared -> sending? -> sent / abandoned) 在同一写事务内迁移。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

from . import crypto

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certs(
  fingerprint   TEXT PRIMARY KEY,     -- 证书 DER 的 SHA-256（密钥摘要）
  subject       TEXT NOT NULL,
  email         TEXT NOT NULL,        -- CN 主邮箱
  san           TEXT NOT NULL,        -- JSON: SAN 邮箱列表
  cert_pem      TEXT NOT NULL,
  nb_epoch      INTEGER NOT NULL,     -- notBefore（解析后的 epoch，GMT）
  na_epoch      INTEGER NOT NULL,     -- notAfter
  issued_seq    INTEGER NOT NULL,     -- 该地址的证书版本号，从 1 开始
  active        INTEGER NOT NULL DEFAULT 1,
  revoked       INTEGER NOT NULL DEFAULT 0,
  revoked_at    INTEGER,
  revoke_reason TEXT,
  created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_certs_email ON certs(email);

-- 通讯录：地址 -> 当前可信证书指纹（撤销/轮换时移动指针）
CREATE TABLE IF NOT EXISTS directory(
  email       TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  updated_at  INTEGER NOT NULL
);

-- 加密策略：domain / identity 两级覆盖；缺省走 settings.default_mode
CREATE TABLE IF NOT EXISTS policies(
  scope_type TEXT NOT NULL,           -- 'domain' | 'identity'
  scope      TEXT NOT NULL,
  mode       TEXT NOT NULL,           -- 'enforce' | 'opportunistic'
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(scope_type, scope)
);

CREATE TABLE IF NOT EXISTS snapshots(
  snapshot_id        TEXT PRIMARY KEY,
  message_id         TEXT NOT NULL,        -- 显式 renew 时允许历史链多行
  sender             TEXT NOT NULL,
  point_in_time      INTEGER NOT NULL,  -- 解析时刻（逻辑时钟）
  state              TEXT NOT NULL,      -- prepared | sent | abandoned
  recipients_json    TEXT NOT NULL,
  policy_json        TEXT NOT NULL,
  cert_digest        TEXT NOT NULL,      -- 冻结的证书摘要（canonical）
  recipients_hash    TEXT NOT NULL,
  required_count     INTEGER NOT NULL,
  optional_count     INTEGER NOT NULL,
  all_required_keyed INTEGER NOT NULL,
  ack_json           TEXT,               -- 缺失可选收件人的显式确认
  envelope_secret    TEXT,               -- 预检冻结的 CEK 派生密钥（重试复用同一 CEK）
  renewed_from       TEXT,
  abandon_reason     TEXT,
  created_at         INTEGER NOT NULL,
  sent_at            INTEGER,
  manifest_id        TEXT
);

CREATE TABLE IF NOT EXISTS manifests(
  manifest_id  TEXT PRIMARY KEY,
  snapshot_id  TEXT NOT NULL,
  message_id   TEXT NOT NULL,
  envelope_id  TEXT NOT NULL,
  canon_json   TEXT NOT NULL,           -- 被签名的规范字节（UTF-8）
  signature    TEXT NOT NULL,           -- RSA-PSS over SHA-256
  sha256       TEXT NOT NULL,
  events_json  TEXT NOT NULL DEFAULT '[]', -- 事后迟到事件（只追加，不改事实）
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS delivery_attempts(
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  manifest_id TEXT,                     -- 预发送失败时可能为空
  message_id  TEXT NOT NULL,
  attempt_no  INTEGER NOT NULL,
  recipient   TEXT NOT NULL,
  transport   TEXT NOT NULL,           -- e2ee | cleartext
  result      TEXT NOT NULL,           -- delivered | failed
  detail      TEXT,
  created_at  INTEGER NOT NULL
);
"""


class Storage:
    def __init__(self, data_dir: str):
        self.data_dir = os.path.abspath(data_dir)
        self.db_path = os.path.join(self.data_dir, "gateway.db")
        self.vault_dir = os.path.join(self.data_dir, "vault")   # 收件人私钥（演示/解密）
        self.outbound_dir = os.path.join(self.data_dir, "outbound")
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.vault_dir, exist_ok=True)
        os.makedirs(self.outbound_dir, exist_ok=True)
        self._lock = threading.Lock()
        self.init_db()
        self._bootstrap_gateway()

    # ---- 连接 -----------------------------------------------------------

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def init_db(self) -> None:
        conn = self.connect()
        try:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)",
                ("default_mode", "enforce"),
            )
        finally:
            conn.close()

    # ---- 逻辑时钟 --------------------------------------------------------

    def now(self, conn: sqlite3.Connection) -> int:
        row = conn.execute(
            "SELECT value FROM settings WHERE key='now_override'"
        ).fetchone()
        if row is not None:
            return int(row["value"])
        return int(time.time())

    def set_clock(self, epoch: int | None) -> None:
        conn = self.connect()
        try:
            if epoch is None:
                conn.execute("DELETE FROM settings WHERE key='now_override'")
            else:
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('now_override',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (str(epoch),),
                )
        finally:
            conn.close()

    # ---- 网关身份密钥 ----------------------------------------------------

    GATEWAY_KEY = "gateway_signing_key.pem"

    def _bootstrap_gateway(self) -> None:
        path = os.path.join(self.data_dir, self.GATEWAY_KEY)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(crypto.gen_rsa_key(2048))
            os.chmod(path, 0o600)

    def gateway_private_pem(self) -> str:
        with open(os.path.join(self.data_dir, self.GATEWAY_KEY)) as f:
            return f.read()

    def gateway_public_pem(self) -> str:
        return crypto.public_pem(self.gateway_private_pem())

    # ---- 收件人私钥库（仅演示：收件人本地解密，发送路径绝不读取） ---------

    def vault_put(self, fingerprint: str, private_pem: str) -> None:
        path = os.path.join(self.vault_dir, fingerprint.replace(":", "") + ".pem")
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(private_pem)
            os.chmod(path, 0o600)

    def vault_get(self, fingerprint: str) -> str | None:
        path = os.path.join(self.vault_dir, fingerprint.replace(":", "") + ".pem")
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return f.read()

    # ---- 通用设置 --------------------------------------------------------

    def get_setting(self, conn: sqlite3.Connection, key: str,
                    default: str | None = None) -> str | None:
        row = conn.execute("SELECT value FROM settings WHERE key=?",
                           (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        conn = self.connect()
        try:
            conn.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
        finally:
            conn.close()
