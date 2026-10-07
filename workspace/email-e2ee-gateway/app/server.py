"""网关启动入口。

用法：
  python3 -m app.server [--host 127.0.0.1] [--port 8080] [--data ./data] [--seed]
"""

from __future__ import annotations

import argparse
from http.server import ThreadingHTTPServer

from .api import Handler
from .db import Storage
from .service import ENFORCE, OPPORTUNISTIC, Gateway


def seed_demo(gw: Gateway) -> None:
    """灌入演示数据：两个内部域（强制）、一个外部合作域（机会性）。"""
    for a in ("alice@corp.example", "bob@corp.example",
              "carol@eng.corp.example"):
        gw.provision(a)
    gw.provision("dave@partner.example")
    gw.set_policy("domain", "corp.example", ENFORCE)
    gw.set_policy("domain", "eng.corp.example", ENFORCE)
    gw.set_policy("domain", "partner.example", OPPORTUNISTIC)
    gw.set_default_mode(ENFORCE)


def make_server(host: str, port: int, data_dir: str,
                seed: bool = False) -> ThreadingHTTPServer:
    store = Storage(data_dir)
    gw = Gateway(store)
    if seed:
        seed_demo(gw)

    class _Handler(Handler):
        pass

    _Handler.gw = gw
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.daemon_threads = True
    return httpd


def main():
    ap = argparse.ArgumentParser(description="企业邮件 E2EE 策略网关")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--data", default="./data")
    ap.add_argument("--seed", action="store_true", help="灌入演示数据")
    args = ap.parse_args()

    httpd = make_server(args.host, args.port, args.data, args.seed)
    print(f"邮件 E2EE 策略网关已启动: http://{args.host}:{args.port}/  "
          f"(数据目录 {args.data})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n关闭中…")
        httpd.shutdown()


if __name__ == "__main__":
    main()
