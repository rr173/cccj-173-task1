"""网关红线场景测试。直接运行：python3 -m pytest -q（无 pytest 时 python3 tests/test_gateway.py）"""

import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import crypto
from app.db import Storage
from app.server import make_server, seed_demo
from app.service import (ENFORCE, OPPORTUNISTIC, Gateway, GatewayError,
                         STATE_ABANDONED, STATE_PREPARED, STATE_SENT)


def body_json(resp):
    return json.loads(resp.read().decode())


class GatewayTestBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="gw-test-")
        self.store = Storage(self.dir)
        self.gw = Gateway(self.store)
        self.provision_all()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def provision_all(self):
        for a in ("alice@corp.example", "bob@corp.example",
                  "carol@eng.corp.example"):
            self.gw.provision(a)
        self.gw.provision("dave@partner.example")
        self.gw.set_policy("domain", "corp.example", ENFORCE)
        self.gw.set_policy("domain", "eng.corp.example", ENFORCE)
        self.gw.set_policy("domain", "partner.example", OPPORTUNISTIC)
        self.gw.set_default_mode(ENFORCE)

    def precheck(self, msg="m1", rcpts=("bob@corp.example",),
                 sender="alice@corp.example", renew=False):
        return self.gw.precheck(msg, sender, list(rcpts), renew=renew)

    def fp_of(self, email_addr):
        for e in self.gw.list_directory():
            if e["email"] == email_addr:
                return e["fingerprint"]
        raise KeyError(email_addr)


class TestPolicyAndPrecheck(GatewayTestBase):
    def test_all_keyed_is_deliverable(self):
        r = self.precheck(rcpts=["bob@corp.example", "carol@eng.corp.example"])
        self.assertTrue(r["deliverable"])
        self.assertEqual(2, len(r["recipients"]))  # 去重排序
        self.assertTrue(all(x["transport"] == "e2ee" for x in r["recipients"]))

    def test_enforce_missing_key_blocks(self):
        # 新外部域，默认 enforce，无密钥
        r = self.precheck(rcpts=["bob@corp.example", "stranger@external.io"])
        self.assertFalse(r["deliverable"])
        self.assertEqual(1, len(r["required_missing"]))
        self.assertEqual("stranger@external.io",
                         r["required_missing"][0]["address"])
        with self.assertRaises(GatewayError) as cm:
            self.gw.send(r["snapshot_id"], b"hello")
        self.assertEqual(422, cm.exception.status)
        self.assertIn("禁止静默降级", cm.exception.message)

    def test_opportunistic_missing_needs_explicit_ack(self):
        r = self.precheck(rcpts=["bob@corp.example", "dave@partner.example"])
        # 先把 dave 移出目录制造缺密钥
        self.gw.remove_from_directory("dave@partner.example")
        r = self.gw.precheck("m2", "alice@corp.example",
                             ["bob@corp.example", "dave@partner.example"])
        self.assertTrue(r["deliverable"])
        self.assertEqual(1, len(r["optional_missing"]))
        # 未确认 -> 拒绝
        with self.assertRaises(GatewayError) as cm:
            self.gw.send(r["snapshot_id"], b"x")
        self.assertEqual("downgrade_blocked", cm.exception.code)
        # 显式确认后放行，清单中明确记录明文
        out = self.gw.send(r["snapshot_id"], b"x",
                           plaintext_ack=["dave@partner.example"])
        m = self.gw.get_manifest(out["manifest_id"])
        tmap = {x["address"]: x["transport"]
                for x in m["document"]["recipients"]}
        self.assertEqual("cleartext", tmap["dave@partner.example"])
        self.assertEqual("e2ee", tmap["bob@corp.example"])

    def test_identity_override_beats_domain(self):
        self.gw.set_policy("identity", "dave@partner.example", ENFORCE)
        self.gw.remove_from_directory("dave@partner.example")
        r = self.precheck("m3", ["dave@partner.example"])
        self.assertFalse(r["deliverable"])
        self.assertEqual("dave@partner.example",
                         r["required_missing"][0]["address"])


class TestSnapshotFreeze(GatewayTestBase):
    def test_rotation_between_precheck_and_send_uses_frozen_cert(self):
        r = self.precheck(rcpts=["bob@corp.example"])
        old_fp = next(x["fingerprint"] for x in r["recipients"])
        # 预检之后轮换 bob 的证书，通讯录指针已指向新证
        rot = self.gw.rotate("bob@corp.example")
        self.assertNotEqual(old_fp, rot["fingerprint"])
        # 发送仍用快照中的旧指纹（旧证未撤销），成功
        out = self.gw.send(r["snapshot_id"], b"frozen!")
        m = self.gw.get_manifest(out["manifest_id"])
        bob = next(x for x in m["document"]["recipients"]
                   if x["address"] == "bob@corp.example")
        self.assertEqual(old_fp, bob["fingerprint"])
        # 收件人用旧私钥可解
        dec = self.gw.recipient_decrypt(out["manifest_id"],
                                        "bob@corp.example")
        self.assertEqual("frozen!", dec["plaintext"])

    def test_revocation_between_precheck_and_send_fails_closed(self):
        r = self.precheck(rcpts=["bob@corp.example"])
        snap_id = r["snapshot_id"]
        fp = self.fp_of("bob@corp.example")
        self.gw.revoke(fp, "compromise discovered")
        with self.assertRaises(GatewayError) as cm:
            self.gw.send(snap_id, b"secret")
        self.assertEqual("key_revoked", cm.exception.code)
        # 快照被作废，且没有产生清单/二次投递
        snap = self.gw.get_snapshot(snap_id)
        self.assertEqual(STATE_ABANDONED, snap["state"])
        # 用重新预检的新快照（bob 无密钥）应阻断
        r2 = self.gw.precheck("m1b", "alice@corp.example",
                              ["bob@corp.example"])
        self.assertFalse(r2["deliverable"])

    def test_directory_removal_between_precheck_and_send(self):
        r = self.precheck("m9", ["bob@corp.example"])
        # 通讯录删除，但证书行仍在（未撤销）——快照指纹仍可发送
        self.gw.remove_from_directory("bob@corp.example")
        out = self.gw.send(r["snapshot_id"], b"still frozen")
        self.assertEqual(STATE_SENT,
                         self.gw.get_snapshot(r["snapshot_id"])["state"])
        m = self.gw.get_manifest(out["manifest_id"])
        self.assertTrue(m["document"]["recipients"])

    def test_expired_cert_at_send_time_fails_closed(self):
        r = self.precheck("m10", ["bob@corp.example"])
        # 把逻辑时钟拨到证书到期之后
        fp = self.fp_of("bob@corp.example")
        conn = self.store.connect()
        na = conn.execute("SELECT na_epoch FROM certs WHERE fingerprint=?",
                          (fp,)).fetchone()["na_epoch"]
        conn.close()
        self.store.set_clock(na + 10)
        try:
            with self.assertRaises(GatewayError) as cm:
                self.gw.send(r["snapshot_id"], b"x")
            self.assertEqual("key_expired", cm.exception.code)
        finally:
            self.store.set_clock(None)

    def test_precheck_at_future_time_sees_expired(self):
        fp = self.fp_of("bob@corp.example")
        conn = self.store.connect()
        na = conn.execute("SELECT na_epoch FROM certs WHERE fingerprint=?",
                          (fp,)).fetchone()["na_epoch"]
        conn.close()
        self.store.set_clock(na + 1)
        try:
            r = self.precheck("m11", ["bob@corp.example"])
            self.assertFalse(r["deliverable"])
            self.assertEqual("expired",
                             r["required_missing"][0]["status"])
        finally:
            self.store.set_clock(None)

    def test_duplicate_precheck_requires_explicit_renew(self):
        r1 = self.precheck("dup", ["bob@corp.example"])
        with self.assertRaises(GatewayError) as cm:
            self.precheck("dup", ["bob@corp.example"])
        self.assertEqual(409, cm.exception.status)
        r2 = self.precheck("dup", ["bob@corp.example"], renew=True)
        self.assertNotEqual(r1["snapshot_id"], r2["snapshot_id"])
        old = self.gw.get_snapshot(r1["snapshot_id"])
        self.assertEqual(STATE_ABANDONED, old["state"])
        # 旧快照不能再发送
        with self.assertRaises(GatewayError) as cm:
            self.gw.send(r1["snapshot_id"], b"x")
        self.assertEqual("snapshot_abandoned", cm.exception.code)

    def test_resend_after_sent_is_rejected(self):
        r = self.precheck("sent1", ["bob@corp.example"])
        self.gw.send(r["snapshot_id"], b"x")
        with self.assertRaises(GatewayError) as cm:
            self.gw.precheck("sent1", "alice@corp.example",
                             ["bob@corp.example"])
        self.assertEqual("already_sent", cm.exception.code)


class TestDeliveryAndRetry(GatewayTestBase):
    def test_transient_failure_then_retry_same_snapshot(self):
        r = self.precheck("retry1", ["bob@corp.example",
                                     "carol@eng.corp.example"])
        snap_id = r["snapshot_id"]
        self.store.set_setting("fail_next_recipient", "bob@corp.example")
        with self.assertRaises(GatewayError) as cm:
            self.gw.send(snap_id, b"payload")
        self.assertEqual(502, cm.exception.status)
        self.assertEqual(STATE_PREPARED,
                         self.gw.get_snapshot(snap_id)["state"])
        # 重试成功，且只产生一次成功投递事实
        out = self.gw.send(snap_id, b"payload")
        m = self.gw.get_manifest(out["manifest_id"])
        attempts = [d for d in m["document"]["deliveries"]]
        self.assertEqual(2, attempts[0]["attempt_no"])
        self.assertTrue(all(d["result"] == "delivered" for d in attempts))

    def test_concurrent_retry_only_one_delivery(self):
        r = self.precheck("conc1", ["bob@corp.example"])
        snap_id = r["snapshot_id"]
        results = []

        def worker():
            try:
                results.append(("ok", self.gw.send(snap_id, b"parallel")))
            except Exception as e:
                results.append(("err", type(e).__name__))

        ts = [threading.Thread(target=worker) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        oks = [x for x in results if x[0] == "ok"]
        # 幂等：所有成功调用返回同一个 manifest_id（首个投递，其余返回既有清单）
        self.assertEqual(len(results), 8)
        self.assertEqual(1, len({x[1]["manifest_id"] for x in oks}))
        # 库里事实只有一份清单、一条成功投递/收件人
        conn = self.store.connect()
        n_man = conn.execute(
            "SELECT COUNT(*) c FROM manifests").fetchone()["c"]
        n_ok = conn.execute(
            "SELECT COUNT(*) c FROM delivery_attempts WHERE result='delivered'"
        ).fetchone()["c"]
        conn.close()
        self.assertEqual(1, n_man)
        self.assertEqual(1, n_ok)

    def test_concurrent_precheck_only_one_snapshot(self):
        out = []

        def worker():
            try:
                out.append(self.gw.precheck(
                    "race-pre", sender="alice@corp.example",
                    recipients=["bob@corp.example"]))
            except GatewayError as e:
                out.append(e)

        ts = [threading.Thread(target=worker) for _ in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        snaps = [x for x in out if not isinstance(x, Exception)]
        self.assertEqual(1, len(snaps))


class TestManifest(GatewayTestBase):
    def _send(self, msg="man1"):
        r = self.precheck(msg, ["bob@corp.example",
                                "carol@eng.corp.example"])
        return self.gw.send(r["snapshot_id"], b"top secret body")

    def test_manifest_signature_verifies(self):
        out = self._send()
        v = self.gw.verify_manifest(out["manifest_id"])
        self.assertTrue(v["valid"], v["checks"])

    def test_tampered_manifest_fails_verification(self):
        out = self._send()
        # 直接篡改数据库中签名文档
        conn = self.store.connect()
        row = conn.execute("SELECT canon_json FROM manifests WHERE manifest_id=?",
                           (out["manifest_id"],)).fetchone()
        doc = json.loads(row["canon_json"])
        doc["sealed_at"] += 1
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE manifests SET canon_json=? WHERE manifest_id=?",
                     (json.dumps(doc, ensure_ascii=False) + "\n",
                      out["manifest_id"]))
        conn.execute("COMMIT")
        conn.close()
        v = self.gw.verify_manifest(out["manifest_id"])
        self.assertFalse(v["valid"])
        self.assertFalse(v["checks"][0]["pass"])  # 签名

    def test_late_revocation_is_appended_not_rewritten(self):
        out = self._send()
        sha_before = out["sha256"]
        fp = self.fp_of("bob@corp.example")
        self.gw.revoke(fp)  # 发送后撤销
        ev = self.gw.record_late_event(out["manifest_id"], "late_revocation",
                                       {"address": "bob@corp.example",
                                        "fingerprint": fp})
        m = self.gw.get_manifest(out["manifest_id"])
        # 已签名事实与哈希不变
        self.assertEqual(sha_before, m["sha256"])
        self.assertTrue(self.gw.verify_manifest(out["manifest_id"])["valid"])
        self.assertEqual("late_revocation", m["events"][-1]["kind"])
        self.assertIn("appended", ev)

    def test_recipient_decryption_and_mac(self):
        out = self._send()
        dec = self.gw.recipient_decrypt(out["manifest_id"],
                                        "carol@eng.corp.example")
        self.assertEqual("top secret body", dec["plaintext"])
        # 非收件人不能解
        with self.assertRaises(GatewayError) as cm:
            self.gw.recipient_decrypt(out["manifest_id"],
                                      "alice@corp.example")
        self.assertEqual(403, cm.exception.status)


class TestHTTPEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="gw-http-")
        cls.httpd = make_server("127.0.0.1", 0, cls.tmp, seed=True)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _req(self, method, path, obj=None):
        data = json.dumps(obj).encode() if obj is not None else None
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_full_flow_over_http(self):
        s, info = self._req("GET", "/api/info")
        self.assertEqual(200, s)
        self.assertIn("gateway_public_key", info)

        s, pc = self._req("POST", "/api/precheck", {
            "message_id": "http-1", "sender": "alice@corp.example",
            "recipients": ["bob@corp.example"]})
        self.assertEqual(201, s)
        self.assertTrue(pc["deliverable"])

        s, sent = self._req("POST",
                            f"/api/snapshots/{pc['snapshot_id']}/send",
                            {"body": "http secret"})
        self.assertEqual(200, s)

        s, v = self._req("GET",
                         f"/api/manifests/{sent['manifest_id']}/verify")
        self.assertEqual(200, s)
        self.assertTrue(v["valid"])

        s, dec = self._req(
            "POST", f"/api/manifests/{sent['manifest_id']}/decrypt",
            {"address": "bob@corp.example"})
        self.assertEqual(200, s)
        self.assertEqual("http secret", dec["plaintext"])

    def test_enforce_block_over_http(self):
        s, pc = self._req("POST", "/api/precheck", {
            "message_id": "http-2", "sender": "alice@corp.example",
            "recipients": ["nobody@nowhere.io"]})
        self.assertFalse(pc["deliverable"])
        s, err = self._req("POST",
                           f"/api/snapshots/{pc['snapshot_id']}/send",
                           {"body": "x"})
        self.assertEqual(422, s)
        self.assertEqual("downgrade_blocked", err["error"])

    def test_revocation_race_over_http(self):
        s, pc = self._req("POST", "/api/precheck", {
            "message_id": "http-3", "sender": "alice@corp.example",
            "recipients": ["carol@eng.corp.example"]})
        s, d = self._req("GET", "/api/directory")
        fp = next(e["fingerprint"] for e in d["entries"]
                  if e["email"] == "carol@eng.corp.example")
        s, _ = self._req("POST", "/api/certs/revoke",
                         {"fingerprint": fp})
        s, err = self._req("POST",
                           f"/api/snapshots/{pc['snapshot_id']}/send",
                           {"body": "x"})
        self.assertEqual(409, s)
        self.assertEqual("key_revoked", err["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
