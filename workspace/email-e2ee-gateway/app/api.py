"""HTTP API：策略 / 通讯录 / 预检 / 发送 / 清单（标准库 http.server）。

路由：
  GET  /api/info                      网关身份公钥、时钟
  POST /api/clock                     管理员拨动逻辑时钟（演示时间点语义）
  GET  /api/policies                  策略列表
  PUT  /api/policies/default          设置缺省模式
  PUT  /api/policies                  设置 domain/identity 覆盖
  DELETE /api/policies                删除覆盖
  GET  /api/directory                 通讯录
  POST /api/directory/provision       新建收件人（签发证书）
  POST /api/directory/cert            登记已有证书 PEM
  POST /api/directory/rotate          轮换证书
  POST /api/certs/revoke              撤销证书
  DELETE /api/directory/<email>       通讯录移除
  GET  /api/certs/<email>/history     证书历史
  POST /api/precheck                  发送预检（冻结快照）
  GET  /api/snapshots/<id>            快照详情
  POST /api/snapshots/<id>/send       按快照发送
  POST /api/simulate/fail-next        注入下一次投递失败（演示重试）
  GET  /api/manifests/<id>            投递清单
  GET  /api/messages/<id>/manifest    按 message_id 查清单
  GET  /api/manifests/<id>/verify     验证清单
  POST /api/manifests/<id>/events     追加迟到事件
  POST /api/manifests/<id>/decrypt    收件人解密演示
"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler

from . import crypto
from .service import Gateway, GatewayError


def _json_default(obj):
    if isinstance(obj, bytes):
        return crypto.b64e(obj)
    raise TypeError(type(obj).__name__)


class Handler(BaseHTTPRequestHandler):
    server_version = "E2EEPolicyGateway/1.0"

    # 由 make_server 注入
    gw: Gateway

    def log_message(self, fmt, *args):  # 安静一点
        pass

    # ---- 工具 ------------------------------------------------------------

    def _send_json(self, obj, status: int = 200):
        body = json.dumps(obj, ensure_ascii=False,
                          default=_json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n == 0:
            return {}
        raw = self.rfile.read(n)
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise GatewayError("bad_json", f"请求体不是合法 JSON: {e}")
        if not isinstance(data, dict):
            raise GatewayError("bad_json", "请求体必须是 JSON 对象")
        return data

    def _error(self, e: GatewayError):
        self._send_json({"error": e.code, "message": e.message,
                         "details": e.details}, e.status)

    # ---- 路由 ------------------------------------------------------------

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")

    def _route(self, method: str):
        try:
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            if path == "/" and method == "GET":
                return self._serve_ui()
            if path.startswith("/ui/") and method == "GET":
                return self._serve_static(path[4:])

            gw = self.gw
            body = self._read_json() if method in ("POST", "PUT") else {}

            if path == "/api/info" and method == "GET":
                from .db import Storage  # noqa
                store: Storage = gw.store
                conn = store.connect()
                try:
                    ov = store.get_setting(conn, "now_override")
                    clock = {"mode": "override", "now": int(ov)} if ov \
                        else {"mode": "system", "now": store.now(conn)}
                finally:
                    conn.close()
                return self._send_json({
                    "service": "enterprise-email-e2ee-policy-gateway",
                    "version": 1,
                    "clock": clock,
                    "gateway_public_key": store.gateway_public_pem(),
                    "gateway_public_key_sha256":
                        crypto.sha256_hex(store.gateway_public_pem().encode()),
                    "policies": gw.list_policies(),
                })

            if path == "/api/clock" and method == "POST":
                epoch = body.get("epoch")
                gw.store.set_clock(int(epoch) if epoch is not None else None)
                return self._send_json({"ok": True, "epoch": epoch})

            if path == "/api/policies" and method == "GET":
                return self._send_json(gw.list_policies())
            if path == "/api/policies" and method == "PUT":
                return self._send_json(gw.set_policy(
                    body["scope_type"], body["scope"], body["mode"]))
            if path == "/api/policies/default" and method == "PUT":
                return self._send_json(gw.set_default_mode(body["mode"]))
            if path == "/api/policies" and method == "DELETE":
                return self._send_json(gw.delete_policy(
                    body["scope_type"], body["scope"]))

            if path == "/api/directory" and method == "GET":
                return self._send_json({"entries": gw.list_directory()})
            if path == "/api/directory/provision" and method == "POST":
                return self._send_json(gw.provision(
                    body["email"], days=int(body.get("days", 365)),
                    san=body.get("san")), 201)
            if path == "/api/directory/cert" and method == "POST":
                return self._send_json(gw.register_cert(
                    body["email"], body["cert_pem"],
                    private_pem=body.get("private_pem")), 201)
            if path == "/api/directory/rotate" and method == "POST":
                return self._send_json(gw.rotate(
                    body["email"], days=int(body.get("days", 365))), 201)
            if path == "/api/certs/revoke" and method == "POST":
                return self._send_json(gw.revoke(
                    body["fingerprint"], body.get("reason", "key compromise")))

            m = re.fullmatch(r"/api/directory/([^/]+)", path)
            if m and method == "DELETE":
                return self._send_json(
                    gw.remove_from_directory(m.group(1)))

            m = re.fullmatch(r"/api/certs/([^/]+)/history", path)
            if m and method == "GET":
                return self._send_json(
                    {"email": m.group(1),
                     "history": gw.cert_history(m.group(1))})

            if path == "/api/precheck" and method == "POST":
                return self._send_json(gw.precheck(
                    body["message_id"], body.get("sender", ""),
                    body["recipients"],
                    renew=bool(body.get("renew", False))), 201)

            m = re.fullmatch(r"/api/snapshots/([^/]+)", path)
            if m and method == "GET":
                return self._send_json(gw.get_snapshot(m.group(1)))

            m = re.fullmatch(r"/api/snapshots/([^/]+)/send", path)
            if m and method == "POST":
                raw_body = body.get("body", "")
                if isinstance(raw_body, str):
                    msg_body = raw_body.encode("utf-8")
                else:
                    msg_body = crypto.b64d(raw_body)
                return self._send_json(gw.send(
                    m.group(1), msg_body,
                    plaintext_ack=body.get("plaintext_ack", []),
                    content_type=body.get("content_type",
                                         "text/plain; charset=utf-8")), 200)

            if path == "/api/simulate/fail-next" and method == "POST":
                gw.store.set_setting("fail_next_recipient",
                                     str(body["recipient"]).strip().lower())
                return self._send_json({"armed": body["recipient"]})

            m = re.fullmatch(r"/api/manifests/([^/]+)", path)
            if m and method == "GET":
                return self._send_json(gw.get_manifest(m.group(1)))

            m = re.fullmatch(r"/api/messages/([^/]+)/manifest", path)
            if m and method == "GET":
                return self._send_json(gw.get_manifest_by_message(m.group(1)))

            m = re.fullmatch(r"/api/manifests/([^/]+)/verify", path)
            if m and method == "GET":
                return self._send_json(gw.verify_manifest(m.group(1)))

            m = re.fullmatch(r"/api/manifests/([^/]+)/events", path)
            if m and method == "POST":
                return self._send_json(gw.record_late_event(
                    m.group(1), body.get("kind", "note"),
                    body.get("detail", {})), 201)

            m = re.fullmatch(r"/api/manifests/([^/]+)/decrypt", path)
            if m and method == "POST":
                return self._send_json(gw.recipient_decrypt(
                    m.group(1), body["address"]))

            self._send_json({"error": "not_found",
                             "message": f"无此路由: {method} {path}"}, 404)
        except GatewayError as e:
            self._error(e)
        except KeyError as e:
            self._error(GatewayError("missing_field", f"缺少字段: {e}", 400))
        except (ValueError, TypeError) as e:
            self._error(GatewayError("bad_request", str(e), 400))
        except BrokenPipeError:
            pass

    # ---- 静态前端 ---------------------------------------------------------

    def _serve_ui(self):
        self._serve_static("index.html", default=True)

    def _serve_static(self, name: str, default: bool = False):
        import os
        base = os.path.join(os.path.dirname(__file__), "web")
        safe = os.path.normpath(os.path.join(base, name))
        if not safe.startswith(base + os.sep) and safe != base:
            return self._send_json({"error": "forbidden"}, 403)
        if not os.path.isfile(safe):
            if default:
                safe = os.path.join(base, "index.html")
            else:
                return self._send_json({"error": "not_found"}, 404)
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
        }.get(os.path.splitext(safe)[1], "application/octet-stream")
        with open(safe, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
