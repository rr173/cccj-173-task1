"""网关核心业务逻辑：策略解析、密钥快照、发送闸门、投递清单。

设计红线（对应需求）：

1. 发送前按 (收件人域, 身份, 时间点) 解析证书，冻结收件人集合与证书摘要。
2. 只有全部 *强制加密(enforce)* 收件人都有可信密钥才允许投递；
   opportunistic 收件人缺密钥不阻断，但必须经发送方显式确认（绝不静默降级）。
3. 预检与发送之间，轮换/撤销/通讯录更新并发发生时，发送只认快照里冻结的指纹；
   快照指纹若在发送时已撤销（或证书到期），失败关闭，绝不换发另一把钥匙。
4. 重试（投递失败/并发重试）复用同一个 snapshot_id、同一把 CEK、同一份清单；
   行级状态机 + IMMEDIATE 事务保证同一邮件只会被投递一次事实。
5. 发送后迟到的撤销/轮换只能作为"事后事件"追加到清单，不能改变已发送事实。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from email.utils import parsedate_to_datetime

from . import crypto
from .db import Storage

ENFORCE = "enforce"
OPPORTUNISTIC = "opportunistic"

STATE_PREPARED = "prepared"
STATE_SENT = "sent"
STATE_ABANDONED = "abandoned"


class GatewayError(Exception):
    def __init__(self, code: str, message: str, status: int = 400,
                 details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details or {}


def _canon(obj) -> bytes:
    """规范 JSON：键排序、无空白、非 ASCII 原样、LF 换行。"""
    return (json.dumps(obj, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":")) + "\n").encode("utf-8")


def _epoch(openssl_date: str) -> int:
    return int(parsedate_to_datetime(openssl_date).timestamp())


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else addr.lower()


class Gateway:
    def __init__(self, storage: Storage):
        self.store = storage
        # 每封邮件的进程内串行点（数据库 IMMEDIATE 事务之外的第二道保险）
        self._msg_locks: dict[str, threading.RLock] = {}
        self._msg_locks_guard = threading.Lock()

    def _lock_for(self, message_id: str) -> threading.RLock:
        with self._msg_locks_guard:
            lk = self._msg_locks.get(message_id)
            if lk is None:
                lk = threading.RLock()
                self._msg_locks[message_id] = lk
            return lk

    # ======================================================================
    # 通讯录（目录服务）：证书登记 / 轮换 / 撤销 / 地址簿更新
    # ======================================================================

    def provision(self, email_addr: str, days: int = 365,
                  san: list[str] | None = None) -> dict:
        """为新地址生成密钥与自签名证书并写入通讯录。私钥只进私钥库。"""
        priv = crypto.gen_rsa_key()
        cert = crypto.gen_self_signed_cert(priv, email_addr, days=days,
                                           extra_emails=san or [])
        return self.register_cert(email_addr, cert, private_pem=priv)

    def register_cert(self, email_addr: str, cert_pem: str,
                      private_pem: str | None = None) -> dict:
        email_addr = email_addr.strip().lower()
        fp = crypto.cert_fingerprint(cert_pem)
        nb, na = crypto.cert_times(cert_pem)
        san_list = [email_addr]
        nb_e, na_e = _epoch(nb), _epoch(na)
        conn = self.store.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            ts = self.store.now(conn)
            seq_row = conn.execute(
                "SELECT COALESCE(MAX(issued_seq),0)+1 AS s FROM certs WHERE email=?",
                (email_addr,),
            ).fetchone()
            seq = seq_row["s"]
            conn.execute(
                "UPDATE certs SET active=0 WHERE email=?", (email_addr,))
            conn.execute(
                "INSERT INTO certs(fingerprint,subject,email,san,cert_pem,"
                "nb_epoch,na_epoch,issued_seq,active,revoked,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,1,0,?) "
                "ON CONFLICT(fingerprint) DO UPDATE SET active=1, revoked=0,"
                "revoked_at=NULL,revoke_reason=NULL",
                (fp, email_addr, email_addr, json.dumps(san_list),
                 cert_pem, nb_e, na_e, seq, ts),
            )
            conn.execute(
                "INSERT INTO directory(email,fingerprint,updated_at) "
                "VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET "
                "fingerprint=excluded.fingerprint,updated_at=excluded.updated_at",
                (email_addr, fp, ts),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        if private_pem:
            self.store.vault_put(fp, private_pem)
        return {"email": email_addr, "fingerprint": fp, "seq": seq,
                "not_before": nb_e, "not_after": na_e, "active": True}

    def rotate(self, email_addr: str, days: int = 365) -> dict:
        """证书轮换：登记新证书，旧证书保留历史（不撤销）。"""
        email_addr = email_addr.strip().lower()
        return self.provision(email_addr, days=days)

    def revoke(self, fingerprint: str, reason: str = "key compromise") -> dict:
        """撤销证书：标记撤销并从通讯录摘掉指针（若当前指向它）。"""
        conn = self.store.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            ts = self.store.now(conn)
            row = conn.execute(
                "SELECT email FROM certs WHERE fingerprint=?",
                (fingerprint,),
            ).fetchone()
            if row is None:
                raise GatewayError("cert_not_found",
                                   f"证书 {fingerprint[:20]}… 不存在", 404)
            conn.execute(
                "UPDATE certs SET revoked=1,revoked_at=?,revoke_reason=? "
                "WHERE fingerprint=?", (ts, reason, fingerprint))
            conn.execute(
                "DELETE FROM directory WHERE fingerprint=?", (fingerprint,))
            conn.execute("COMMIT")
            return {"fingerprint": fingerprint, "revoked_at": ts,
                    "reason": reason}
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def remove_from_directory(self, email_addr: str) -> dict:
        """通讯录更新：移除地址（离职/离组），证书历史保留。"""
        email_addr = email_addr.strip().lower()
        conn = self.store.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute("DELETE FROM directory WHERE email=?",
                               (email_addr,))
            if cur.rowcount == 0:
                raise GatewayError("not_in_directory",
                                   f"{email_addr} 不在通讯录", 404)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return {"email": email_addr, "removed": True}

    def list_directory(self) -> list[dict]:
        conn = self.store.connect()
        try:
            rows = conn.execute(
                "SELECT d.email,d.fingerprint,d.updated_at,"
                "c.issued_seq,c.nb_epoch,c.na_epoch,c.revoked "
                "FROM directory d JOIN certs c ON c.fingerprint=d.fingerprint "
                "ORDER BY d.email"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def cert_history(self, email_addr: str) -> list[dict]:
        conn = self.store.connect()
        try:
            rows = conn.execute(
                "SELECT fingerprint,issued_seq,active,revoked,revoked_at,"
                "revoke_reason,nb_epoch,na_epoch,created_at FROM certs "
                "WHERE email=? ORDER BY issued_seq", (email_addr.strip().lower(),)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_cert_pem(self, fingerprint: str) -> str | None:
        conn = self.store.connect()
        try:
            row = conn.execute("SELECT cert_pem FROM certs WHERE fingerprint=?",
                               (fingerprint,)).fetchone()
            return row["cert_pem"] if row else None
        finally:
            conn.close()

    # ======================================================================
    # 策略
    # ======================================================================

    def set_default_mode(self, mode: str) -> dict:
        if mode not in (ENFORCE, OPPORTUNISTIC):
            raise GatewayError("bad_mode", f"未知策略模式 {mode}")
        self.store.set_setting("default_mode", mode)
        return {"default_mode": mode}

    def set_policy(self, scope_type: str, scope: str, mode: str) -> dict:
        if scope_type not in ("domain", "identity"):
            raise GatewayError("bad_scope", "scope_type 必须是 domain/identity")
        if mode not in (ENFORCE, OPPORTUNISTIC):
            raise GatewayError("bad_mode", f"未知策略模式 {mode}")
        scope = scope.strip().lower()
        conn = self.store.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            ts = self.store.now(conn)
            conn.execute(
                "INSERT INTO policies(scope_type,scope,mode,updated_at) "
                "VALUES(?,?,?,?) ON CONFLICT(scope_type,scope) DO UPDATE SET "
                "mode=excluded.mode,updated_at=excluded.updated_at",
                (scope_type, scope, mode, ts))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return {"scope_type": scope_type, "scope": scope, "mode": mode}

    def delete_policy(self, scope_type: str, scope: str) -> dict:
        conn = self.store.connect()
        try:
            cur = conn.execute(
                "DELETE FROM policies WHERE scope_type=? AND scope=?",
                (scope_type, scope.strip().lower()))
            if cur.rowcount == 0:
                raise GatewayError("policy_not_found", "策略不存在", 404)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return {"deleted": True}

    def list_policies(self) -> dict:
        conn = self.store.connect()
        try:
            rows = conn.execute(
                "SELECT scope_type,scope,mode,updated_at FROM policies "
                "ORDER BY scope_type,scope").fetchall()
            return {
                "default_mode": self.store.get_setting(conn, "default_mode",
                                                        ENFORCE),
                "overrides": [dict(r) for r in rows],
            }
        finally:
            conn.close()

    def _resolve_mode(self, conn, addr: str) -> tuple[str, str]:
        """返回 (mode, 命中来源说明)。identity 覆盖 > domain 覆盖 > 缺省。"""
        ident = conn.execute(
            "SELECT mode FROM policies WHERE scope_type='identity' AND scope=?",
            (addr,)).fetchone()
        if ident:
            return ident["mode"], f"identity:{addr}"
        dom = conn.execute(
            "SELECT mode FROM policies WHERE scope_type='domain' AND scope=?",
            (_domain(addr),)).fetchone()
        if dom:
            return dom["mode"], f"domain:{_domain(addr)}"
        return self.store.get_setting(conn, "default_mode", ENFORCE), "default"

    # ======================================================================
    # 时间点证书解析（只读快照，冻结进 snapshot）
    # ======================================================================

    def _resolve_at(self, conn, addr: str, pit: int) -> dict:
        """在 pit 时刻解析地址的可信证书。

        可信条件：通讯录当前指针 == 证书指纹，且未撤销、未到期/未生效。
        """
        d = conn.execute(
            "SELECT fingerprint,updated_at FROM directory WHERE email=?",
            (addr,)).fetchone()
        if d is None:
            return {"address": addr, "status": "no_directory_entry"}
        c = conn.execute(
            "SELECT fingerprint,nb_epoch,na_epoch,revoked,active,issued_seq "
            "FROM certs WHERE fingerprint=?", (d["fingerprint"],)).fetchone()
        if c is None:
            return {"address": addr, "status": "cert_missing"}
        if c["revoked"]:
            return {"address": addr, "status": "revoked",
                    "fingerprint": c["fingerprint"]}
        if pit < c["nb_epoch"]:
            return {"address": addr, "status": "not_yet_valid",
                    "fingerprint": c["fingerprint"],
                    "not_before": c["nb_epoch"]}
        if pit >= c["na_epoch"]:
            return {"address": addr, "status": "expired",
                    "fingerprint": c["fingerprint"],
                    "not_after": c["na_epoch"]}
        return {"address": addr, "status": "keyed",
                "fingerprint": c["fingerprint"], "issued_seq": c["issued_seq"],
                "directory_updated_at": d["updated_at"],
                "not_before": c["nb_epoch"], "not_after": c["na_epoch"]}

    # ======================================================================
    # 预检：冻结收件人集合 + 证书摘要 -> 密钥快照
    # ======================================================================

    def precheck(self, message_id: str, sender: str, recipients: list[str],
                 renew: bool = False) -> dict:
        if not message_id:
            raise GatewayError("bad_message", "缺少 message_id")
        addrs = sorted({a.strip().lower() for a in recipients if a.strip()})
        if not addrs:
            raise GatewayError("bad_recipients", "收件人集合为空")
        sender = sender.strip().lower()

        with self._lock_for(message_id):
            conn = self.store.connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                pit = self.store.now(conn)

                existing = conn.execute(
                    "SELECT snapshot_id,state,abandon_reason FROM snapshots "
                    "WHERE message_id=? ORDER BY created_at DESC, rowid DESC "
                    "LIMIT 1", (message_id,)).fetchone()
                if existing:
                    if existing["state"] == STATE_SENT:
                        raise GatewayError(
                            "already_sent",
                            f"邮件 {message_id} 已投递，不允许重新预检（防重放）",
                            409)
                    if existing["state"] == STATE_PREPARED and not renew:
                        raise GatewayError(
                            "precheck_exists",
                            "该邮件已有已冻结的预检快照；如确需以当前目录重新冻结，"
                            "请显式 renew=true（旧快照将作废）",
                            409,
                            {"existing_snapshot_id": existing["snapshot_id"]})
                    if renew and existing["state"] == STATE_PREPARED:
                        conn.execute(
                            "UPDATE snapshots SET state=?,abandon_reason=? "
                            "WHERE snapshot_id=?",
                            (STATE_ABANDONED, "renewed by explicit re-precheck",
                             existing["snapshot_id"]))

                recipient_reports = []
                required_missing, optional_missing = [], []
                for addr in addrs:
                    mode, source = self._resolve_mode(conn, addr)
                    res = self._resolve_at(conn, addr, pit)
                    entry = {"address": addr, "domain": _domain(addr),
                             "mode": mode, "policy_source": source, **res}
                    if res["status"] == "keyed":
                        entry["transport"] = "e2ee"
                    else:
                        entry["transport"] = "cleartext"
                        if mode == ENFORCE:
                            required_missing.append(entry)
                        else:
                            optional_missing.append(entry)
                    recipient_reports.append(entry)

                cert_digest = crypto.sha256_hex(
                    _canon({"recipients": [
                        {"address": r["address"],
                         "fingerprint": r.get("fingerprint")}
                        for r in recipient_reports
                    ]}))
                recipients_hash = crypto.sha256_hex(_canon(addrs))

                snapshot_id = "snap_" + crypto.random_hex(12)
                policy_snapshot = self.list_policies()
                envelope_secret = crypto.new_cek()
                renewed_from = existing["snapshot_id"] \
                    if (existing and renew
                        and existing["state"] == STATE_ABANDONED) else None
                conn.execute(
                    "INSERT INTO snapshots(snapshot_id,message_id,sender,"
                    "point_in_time,state,recipients_json,policy_json,"
                    "cert_digest,recipients_hash,required_count,"
                    "optional_count,all_required_keyed,envelope_secret,"
                    "renewed_from,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (snapshot_id, message_id, sender, pit, STATE_PREPARED,
                     json.dumps(recipient_reports, ensure_ascii=False),
                     json.dumps(policy_snapshot, ensure_ascii=False),
                     cert_digest, recipients_hash,
                     len(required_missing) + sum(
                         1 for r in recipient_reports if r["mode"] == ENFORCE
                         and r["status"] == "keyed"),
                     len(optional_missing) + sum(
                         1 for r in recipient_reports
                         if r["mode"] == OPPORTUNISTIC
                         and r["status"] == "keyed"),
                     1 if not required_missing else 0, envelope_secret,
                     renewed_from, pit))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

        return {
            "snapshot_id": snapshot_id,
            "message_id": message_id,
            "point_in_time": pit,
            "state": STATE_PREPARED,
            "all_required_keyed": not required_missing,
            "required_missing": [
                {"address": e["address"], "status": e["status"],
                 "policy_source": e["policy_source"]}
                for e in required_missing],
            "optional_missing": [
                {"address": e["address"], "status": e["status"],
                 "policy_source": e["policy_source"]}
                for e in optional_missing],
            "recipients": recipient_reports,
            "cert_digest": cert_digest,
            "recipients_hash": recipients_hash,
            "deliverable": not required_missing,
            "requires_ack": bool(optional_missing),
        }

    # ======================================================================
    # 发送：只认快照；撤销闸门失败关闭；重试幂等
    # ======================================================================

    def get_snapshot(self, snapshot_id: str, conn=None) -> dict:
        own = conn is None
        conn = conn or self.store.connect()
        try:
            row = conn.execute("SELECT * FROM snapshots WHERE snapshot_id=?",
                               (snapshot_id,)).fetchone()
            if row is None:
                raise GatewayError("snapshot_not_found",
                                   f"快照 {snapshot_id} 不存在", 404)
            d = dict(row)
            d["recipients"] = json.loads(d.pop("recipients_json"))
            d["policy"] = json.loads(d.pop("policy_json"))
            d["ack"] = json.loads(d["ack_json"]) if d["ack_json"] else None
            return d
        finally:
            if own:
                conn.close()

    def send(self, snapshot_id: str, body: bytes,
             plaintext_ack: list[str] | None = None,
             content_type: str = "text/plain; charset=utf-8") -> dict:
        """按已冻结快照发送。重试（含并发重试）幂等：同一邮件只投递一次。"""
        ack_set = {a.strip().lower() for a in (plaintext_ack or [])}
        snap = self.get_snapshot(snapshot_id)
        with self._lock_for(snap["message_id"]):
            return self._send_locked(snapshot_id, body, ack_set, content_type)

    def _send_locked(self, snapshot_id: str, body: bytes, ack_set: set[str],
                     content_type: str) -> dict:
        snap = self.get_snapshot(snapshot_id)
        message_id = snap["message_id"]
        with self._lock_for(message_id):  # RLock，send() 已持有时可重入
            conn = self.store.connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                # 重新加载行并加状态判定（前一个并发请求可能已经投递）
                row = conn.execute(
                    "SELECT * FROM snapshots WHERE snapshot_id=?",
                    (snapshot_id,)).fetchone()
                if row is None:
                    raise GatewayError("snapshot_not_found", "快照不存在", 404)
                if row["state"] == STATE_SENT:
                    # 幂等重试：返回既有清单，绝不二次投递
                    return self._load_manifest(conn, row["manifest_id"],
                                               idempotent_retry=True)
                if row["state"] == STATE_ABANDONED:
                    raise GatewayError(
                        "snapshot_abandoned",
                        "该快照已作废（被显式 renew 取代），不能用于发送；"
                        "请基于当前目录重新预检", 409,
                        {"reason": row["abandon_reason"]})

                recipients = json.loads(row["recipients_json"])
                pit = row["point_in_time"]
                now = self.store.now(conn)

                if ack_set:
                    conn.execute(
                        "UPDATE snapshots SET ack_json=? WHERE snapshot_id=?",
                        (json.dumps(sorted(ack_set), ensure_ascii=False),
                         snapshot_id))

                e2ee, cleartext = [], []
                for r in recipients:
                    addr = r["address"]
                    if r["status"] != "keyed":
                        # 只有 opportunistic 且在显式确认名单里才允许明文
                        if r["mode"] != OPPORTUNISTIC or addr not in ack_set:
                            raise GatewayError(
                                "downgrade_blocked",
                                f"收件人 {addr} 无可用可信密钥（{r['status']}）"
                                f"且未取得显式明文确认；禁止静默降级", 422,
                                {"address": addr, "status": r["status"],
                                 "mode": r["mode"]})
                        cleartext.append(r)
                        continue
                    # 撤销闸门：重新核对冻结指纹（不重新解析目录，只查同一指纹）
                    c = conn.execute(
                        "SELECT revoked,revoked_at,revoke_reason,nb_epoch,"
                        "na_epoch,active,cert_pem FROM certs WHERE fingerprint=?",
                        (r["fingerprint"],)).fetchone()
                    if c is None:
                        self._abandon(conn, row,
                                      f"冻结证书 {r['fingerprint'][:16]}… "
                                      "已不在库中")
                        raise GatewayError(
                            "cert_gone",
                            f"收件人 {addr} 的冻结证书已从目录消失，失败关闭",
                            422)
                    if c["revoked"]:
                        self._abandon(conn, row,
                                      f"冻结证书在发送时已被撤销 "
                                      f"(revoked_at={c['revoked_at']})")
                        raise GatewayError(
                            "key_revoked",
                            f"收件人 {addr} 的冻结证书在预检后被撤销；"
                            "本次投递失败关闭，不换发其他密钥",
                            409, {"address": addr,
                                  "revoked_at": c["revoked_at"],
                                  "reason": c["revoke_reason"]})
                    if now >= c["na_epoch"]:
                        self._abandon(conn, row, "冻结证书已到期")
                        raise GatewayError(
                            "key_expired",
                            f"收件人 {addr} 的冻结证书已到期，失败关闭", 409,
                            {"address": addr, "not_after": c["na_epoch"]})
                    # 注意：active=0（轮换后旧证仍有效）不阻断——快照优先
                    e2ee.append((r, c["cert_pem"]))

                # ---- 构造信封：复用快照冻结的 CEK（重试也同一把） ----
                cek = row["envelope_secret"]
                envelope_id = crypto.envelope_id()
                header = {
                    "v": 1,
                    "envelope_id": envelope_id,
                    "message_id": message_id,
                    "sender": row["sender"],
                    "alg": "AES-256-CBC+HMAC-SHA256",
                    "wrap": "RSA-OAEP-SHA256",
                    "content_type": content_type,
                }
                box = crypto.encrypt_body(cek, body, aad=_canon(header))
                wrapped = []
                for r, cert_pem in e2ee:
                    wrapped.append({
                        "address": r["address"],
                        "mode": r["mode"],
                        "fingerprint": r["fingerprint"],
                        "issued_seq": r.get("issued_seq"),
                        "wrapped_key": crypto.rsa_wrap(cert_pem, cek),
                    })
                envelope = {"header": header, "body": box,
                            "wrapped_keys": wrapped}

                # ---- 投递（写出站文件；可注入失败以验证重试） ----
                attempt_no = conn.execute(
                    "SELECT COALESCE(MAX(attempt_no),0)+1 AS n "
                    "FROM delivery_attempts WHERE message_id=?",
                    (message_id,)).fetchone()["n"]
                results = self._deliver(conn, message_id, attempt_no,
                                        envelope, e2ee, cleartext, body)
                failed = [x for x in results if x["result"] == "failed"]
                if failed:
                    conn.execute("COMMIT")
                    conn.close()
                    raise GatewayError(
                        "delivery_failed",
                        "部分收件人投递失败；快照保持 prepared，可用同一快照重试",
                        502, {"snapshot_id": snapshot_id,
                              "failed": [f["address"] for f in failed]})

                # ---- 封签清单（事实冻结） ----
                manifest_id = "man_" + crypto.random_hex(12)
                manifest_doc = {
                    "v": 1,
                    "manifest_id": manifest_id,
                    "snapshot_id": snapshot_id,
                    "envelope_id": envelope_id,
                    "message_id": message_id,
                    "sender": row["sender"],
                    "precheck_point_in_time": pit,
                    "sealed_at": now,
                    "policy_snapshot": json.loads(row["policy_json"]),
                    "recipients_hash": row["recipients_hash"],
                    "cert_digest": row["cert_digest"],
                    "recipients": [
                        {"address": r["address"], "mode": r["mode"],
                         "transport": "e2ee",
                         "fingerprint": r["fingerprint"],
                         "issued_seq": r.get("issued_seq")}
                        for r, _ in e2ee
                    ] + [
                        {"address": r["address"], "mode": r["mode"],
                         "transport": "cleartext",
                         "acknowledged_at": now,
                         "reason": r["status"]}
                        for r in cleartext
                    ],
                    "envelope_sha256": crypto.sha256_hex(_canon(envelope)),
                    "deliveries": results,
                }
                canon = _canon(manifest_doc)
                signature = crypto.pss_sign(
                    self.store.gateway_private_pem(), canon)
                conn.execute(
                    "INSERT INTO manifests(manifest_id,snapshot_id,message_id,"
                    "envelope_id,canon_json,signature,sha256,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (manifest_id, snapshot_id, message_id, envelope_id,
                     canon.decode("utf-8"), signature,
                     crypto.sha256_hex(canon), now))
                conn.execute(
                    "UPDATE snapshots SET state=?,sent_at=?,manifest_id=? "
                    "WHERE snapshot_id=?",
                    (STATE_SENT, now, manifest_id, snapshot_id))
                self._write_outbound(manifest_id, envelope, manifest_doc,
                                     signature, e2ee, cleartext, body)
                conn.execute("COMMIT")
                return {
                    "manifest_id": manifest_id,
                    "snapshot_id": snapshot_id,
                    "message_id": message_id,
                    "envelope_id": envelope_id,
                    "state": STATE_SENT,
                    "sealed_at": now,
                    "sha256": crypto.sha256_hex(canon),
                    "recipients": manifest_doc["recipients"],
                }
            except GatewayError:
                raise
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass

    def _abandon(self, conn, row, reason: str) -> None:
        """在发送事务中把快照标记为 abandoned 并立即提交（失败关闭留痕）。"""
        conn.execute(
            "UPDATE snapshots SET state=?,abandon_reason=? WHERE snapshot_id=?",
            (STATE_ABANDONED, reason, row["snapshot_id"]))
        conn.execute("COMMIT")

    # 投递失败注入：设置 settings.fail_next_recipient=<addr>，下次投递该人失败
    def _deliver(self, conn, message_id: str, attempt_no: int,
                 envelope: dict, e2ee: list, cleartext: list,
                 body: bytes) -> list[dict]:
        fail_addr = self.store.get_setting(conn, "fail_next_recipient")
        results = []
        now = self.store.now(conn)
        targets = [(r, "e2ee") for r, _ in e2ee] + \
                  [(r, "cleartext") for r in cleartext]
        for r, transport in targets:
            addr = r["address"]
            if fail_addr and addr == fail_addr.strip().lower():
                detail = "injected transient delivery failure"
                result = "failed"
            else:
                detail, result = "accepted by outbound MTA", "delivered"
            conn.execute(
                "INSERT INTO delivery_attempts(manifest_id,message_id,"
                "attempt_no,recipient,transport,result,detail,created_at) "
                "VALUES(NULL,?,?,?,?,?,?,?)",
                (message_id, attempt_no, addr, transport, result,
                 detail, now))
            results.append({"address": addr, "transport": transport,
                            "result": result, "detail": detail,
                            "attempt_no": attempt_no})
        if fail_addr:
            conn.execute("DELETE FROM settings WHERE key='fail_next_recipient'")
        return results

    def _write_outbound(self, manifest_id: str, envelope: dict,
                        manifest_doc: dict, signature: str,
                        e2ee: list, cleartext: list, body: bytes) -> None:
        base = os.path.join(self.store.outbound_dir, manifest_id)
        os.makedirs(base, exist_ok=True)
        with open(os.path.join(base, "envelope.json"), "w") as f:
            json.dump(envelope, f, ensure_ascii=False, indent=2)
        with open(os.path.join(base, "manifest.json"), "w") as f:
            json.dump({"document": manifest_doc, "signature": signature,
                       "gateway_public_key":
                           self.store.gateway_public_pem()}, f,
                      ensure_ascii=False, indent=2)
        for r, _ in e2ee:
            d = os.path.join(base, r["address"].replace("@", "_at_"))
            os.makedirs(d, exist_ok=True)
            wk = next(w for w in envelope["wrapped_keys"]
                      if w["address"] == r["address"])
            with open(os.path.join(d, "delivery.txt"), "w") as f:
                f.write(f"to: {r['address']}\ntransport: e2ee\n"
                        f"envelope: ../envelope.json\n"
                        f"your_wrapped_key: {wk['wrapped_key']}\n")
        for r in cleartext:
            d = os.path.join(base, r["address"].replace("@", "_at_"))
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "delivery.txt"), "w") as f:
                f.write(f"to: {r['address']}\ntransport: cleartext "
                        f"(sender-acknowledged)\n\n")
                f.write(body.decode("utf-8", errors="replace"))

    # ======================================================================
    # 清单：查询 / 验证 / 事后迟到事件
    # ======================================================================

    def _load_manifest(self, conn, manifest_id: str,
                       idempotent_retry: bool = False) -> dict:
        row = conn.execute("SELECT * FROM manifests WHERE manifest_id=?",
                           (manifest_id,)).fetchone()
        if row is None:
            raise GatewayError("manifest_not_found", "清单不存在", 404)
        doc = json.loads(row["canon_json"])
        return {
            "manifest_id": manifest_id,
            "snapshot_id": row["snapshot_id"],
            "message_id": row["message_id"],
            "envelope_id": row["envelope_id"],
            "state": STATE_SENT,
            "sealed_at": doc.get("sealed_at"),
            "sha256": row["sha256"],
            "signature": row["signature"],
            "document": doc,
            "events": json.loads(row["events_json"]),
            "idempotent_retry": idempotent_retry,
        }

    def get_manifest(self, manifest_id: str) -> dict:
        conn = self.store.connect()
        try:
            return self._load_manifest(conn, manifest_id)
        finally:
            conn.close()

    def get_manifest_by_message(self, message_id: str) -> dict:
        conn = self.store.connect()
        try:
            row = conn.execute(
                "SELECT manifest_id FROM manifests WHERE message_id=?",
                (message_id,)).fetchone()
            if row is None:
                raise GatewayError("manifest_not_found",
                                   f"邮件 {message_id} 尚无投递清单", 404)
            return self._load_manifest(conn, row["manifest_id"])
        finally:
            conn.close()

    def record_late_event(self, manifest_id: str, kind: str,
                          detail: dict) -> dict:
        """发送后迟到发现（撤销/轮换/通讯录变更）：只追加，不改已签名事实。"""
        if kind not in ("late_revocation", "late_rotation",
                        "directory_update", "note"):
            raise GatewayError("bad_event", "未知事件类型")
        conn = self.store.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT events_json,created_at FROM manifests WHERE manifest_id=?",
                (manifest_id,)).fetchone()
            if row is None:
                raise GatewayError("manifest_not_found", "清单不存在", 404)
            events = json.loads(row["events_json"])
            event = {"at": self.store.now(conn), "kind": kind,
                     "detail": detail}
            events.append(event)
            conn.execute("UPDATE manifests SET events_json=? WHERE manifest_id=?",
                         (json.dumps(events, ensure_ascii=False), manifest_id))
            conn.execute("COMMIT")
            return {"appended": event,
                    "note": "事件仅附加在签名文档之外，已投递事实与签名不变"}
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def verify_manifest(self, manifest_id: str) -> dict:
        """任何人可用网关公钥独立验证清单：签名 + 哈希 + 内部一致性。"""
        m = self.get_manifest(manifest_id)
        canon = _canon(m["document"])
        checks = []
        ok_sig = crypto.pss_verify(self.store.gateway_public_pem(),
                                   canon, m["signature"])
        checks.append({"check": "rsa_pss_signature", "pass": ok_sig})
        ok_hash = crypto.sha256_hex(canon) == m["sha256"]
        checks.append({"check": "canonical_sha256", "pass": ok_hash,
                       "expected": m["sha256"],
                       "actual": crypto.sha256_hex(canon)})
        # 收件人集合哈希与冻结摘要一致
        addrs = sorted(r["address"] for r in m["document"]["recipients"])
        ok_rh = crypto.sha256_hex(_canon(addrs)) == \
            m["document"]["recipients_hash"]
        checks.append({"check": "recipients_hash", "pass": ok_rh})
        # 快照实际内容与清单一致
        snap = self.get_snapshot(m["snapshot_id"])
        ok_snap = snap["cert_digest"] == m["document"]["cert_digest"] and \
            snap["state"] == STATE_SENT and \
            snap["manifest_id"] == manifest_id
        checks.append({"check": "snapshot_binding", "pass": ok_snap})
        # 每个 e2ee 收件人的指纹在清单与快照间一致
        snap_fps = {r["address"]: r.get("fingerprint")
                    for r in snap["recipients"] if r["status"] == "keyed"}
        mismatches = []
        for r in m["document"]["recipients"]:
            if r["transport"] == "e2ee" and \
                    snap_fps.get(r["address"]) != r["fingerprint"]:
                mismatches.append(r["address"])
        checks.append({"check": "frozen_fingerprints",
                       "pass": not mismatches, "mismatches": mismatches})
        return {
            "manifest_id": manifest_id,
            "valid": all(c["pass"] for c in checks),
            "checks": checks,
            "late_events": m["events"],
            "gateway_public_key_sha256":
                crypto.sha256_hex(self.store.gateway_public_pem().encode()),
        }

    def recipient_decrypt(self, manifest_id: str, address: str) -> dict:
        """收件人侧解密演示：从私钥库取私钥解封 CEK 并解密正文。"""
        m = self.get_manifest(manifest_id)
        address = address.strip().lower()
        r = next((x for x in m["document"]["recipients"]
                  if x["address"] == address), None)
        if r is None:
            raise GatewayError("not_recipient", "该地址不在清单收件人中", 403)
        if r["transport"] != "e2ee":
            return {"address": address, "transport": "cleartext",
                    "note": "该收件人为显式确认的明文投递，无需解密"}
        base = os.path.join(self.store.outbound_dir, manifest_id)
        with open(os.path.join(base, "envelope.json")) as f:
            envelope = json.load(f)
        wk = next(w for w in envelope["wrapped_keys"]
                  if w["address"] == address)
        priv = self.store.vault_get(r["fingerprint"])
        if priv is None:
            raise GatewayError("no_private_key", "私钥库中无该收件人私钥", 404)
        cek = crypto.rsa_unwrap(priv, wk["wrapped_key"])
        pt = crypto.decrypt_body(cek, envelope["body"],
                                 aad=_canon(envelope["header"]))
        return {"address": address, "transport": "e2ee",
                "fingerprint": r["fingerprint"],
                "plaintext": pt.decode("utf-8", errors="replace")}
