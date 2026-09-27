#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""PathScan 的本地测试靶机。

用法::

    python tests/target_server.py 8000          # 正常站点
    python tests/target_server.py 8000 soft404  # 软 404（任意路径都 200）
    python tests/target_server.py 8000 nohost   # 无 Apache 后缀处理（.php 全 404）

正常站点上真实存在的路径：
    /admin            200
    /admin/backend    200   （递归第 2 层）
    /api              301 -> /api/v2
    /backup.zip       403
    /index.html       200
    /login            200
    /robots.txt       200

其余任意路径 404。所有响应都带 Content-Length。
"""

import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

EXISTING = {
    "/": (200, b"root"),
    "/admin": (200, b"admin panel"),
    "/admin/": (200, b"admin panel"),
    "/admin/backend": (200, b"backend"),
    "/admin/backend/users": (200, b"users list"),
    "/api": (301, b""),
    "/api/": (301, b""),
    "/api/v2": (200, b"v2"),
    "/backup.zip": (403, b"forbidden"),
    "/index.html": (200, b"<html>index</html>"),
    "/login": (200, b"login page"),
    "/login.html": (200, b"login page"),
    "/robots.txt": (200, b"User-agent: *\nDisallow: /admin\n"),
    "/wp-login.php": (200, b"wp"),
}

REDIRECT_TO = {"/api": "/api/v2", "/api/": "/api/v2"}

MODE = sys.argv[2] if len(sys.argv) > 2 else "normal"


class Handler(BaseHTTPRequestHandler):
    # HTTP/1.0 让每个响应都用 Connection: close 收尾，免得单连接串行化
    protocol_version = "HTTP/1.0"
    request_count = [0]

    def log_message(self, fmt, *args):
        pass

    def _respond(self, code, body, location=None):
        self.send_response(code)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self):
        path = self.path.split("?")[0]

        if MODE == "soft404":
            # 对任意路径都回 200 —— 扫描器应识别出软 404 并终止
            return self._respond(200, b"soft 404 page for " + path.encode())

        if MODE == "nohost":
            # 模拟未装 PHP：任何 .php 都 404，其余正常
            if path.endswith(".php"):
                return self._respond(404, b"not found")
            if path.endswith(".html"):
                # .html 也拒绝，用于验证「每个后缀单独探测」
                return self._respond(404, b"not found")

        if path in EXISTING:
            code, body = EXISTING[path]
            return self._respond(code, body, REDIRECT_TO.get(path))

        return self._respond(404, b"not found")

    do_GET = _handle
    do_HEAD = _handle
    do_POST = _handle


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    sys.stderr.write("target on http://127.0.0.1:%d mode=%s\n" % (port, MODE))
    sys.stderr.flush()
    srv.serve_forever()


if __name__ == "__main__":
    main()
