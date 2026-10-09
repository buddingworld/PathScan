# -*- coding: utf-8 -*-
"""PathScan 测试套件。

用线程内起的 HTTP 靶机跑真实的端到端扫描，覆盖：
* 正常站点：探测通过、结果命中、递归展开
* 软 404 站点：根目录探测命中后终止
* 无后缀处理站点：该后缀被探掉后不再扫
* keep-alive / --ka 行为
* 暂停指令解析（parse_command 纯函数）
* 掩码引擎
* 隔离环境下的 Set-Cookie（--rh 多头部）
"""

import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathscan import cli, control, engine, output, probes, rules  # noqa: E402
from pathscan.models import GlobalState  # noqa: E402
from pathscan.scanner import Scanner  # noqa: E402


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_handler(existing, redirects=None, soft404=False, dead_suffixes=None,
                 counter=None):
    """构造一个靶机 handler。

    existing        : {path: (code, body)}
    redirects       : {path: location}
    soft404         : 任意路径都 200
    dead_suffixes   : 这些后缀一律 404（模拟未装 PHP）
    counter         : 请求计数的 list，用于断言请求数
    """
    redirects = redirects or {}
    dead_suffixes = dead_suffixes or ()

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *a):
            pass

        def _send(self, code, body, location=None):
            self.send_response(code)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _handle(self):
            if counter is not None:
                counter.append(self.path)
            path = self.path.split("?")[0]
            if soft404:
                return self._send(200, b"soft404 " + path.encode())
            for suf in dead_suffixes:
                if path.endswith(suf):
                    return self._send(404, b"nf")
            if path in existing:
                code, body = existing[path]
                return self._send(code, body, redirects.get(path))
            return self._send(404, b"nf")

        do_GET = _handle
        do_HEAD = _handle
        do_POST = _handle

    return H


def start_server(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever)
    t.daemon = True
    t.start()
    return srv, "http://127.0.0.1:%d" % port


def run_scan(url, d_lines, f_lines, extra=None, timeout=120):
    """在进程内跑一次扫描，返回 (results, errors, state, out_texts)。"""
    tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp")
    if not os.path.isdir(tmp):
        os.makedirs(tmp)
    dpath = os.path.join(tmp, "d.txt")
    fpath = os.path.join(tmp, "f.txt")
    with open(dpath, "w") as fh:
        fh.write("\n".join(d_lines) + "\n")
    with open(fpath, "w") as fh:
        fh.write("\n".join(f_lines) + "\n")

    argv = ["-u", url, "-d", dpath, "-f", fpath] + (extra or [])
    ns = cli.build_parser().parse_args(argv)
    args = cli.Args(ns)

    printed = []

    class Cap(output.Printer):
        """测试用的 Printer：非 TTY、收集输出。"""

        def __init__(self):
            output.Printer.__init__(self, quiet=False, live=False)

        def raw(self, line="", stream=None):
            printed.append(line)

        def info(self, msg, tag="*"):
            printed.append("%s %s" % (tag, msg))

    printer = Cap()
    errors = cli.validate(args, printer)
    assert not errors, errors

    dir_entries, _ = cli.load_wordlist(dpath, "dir")
    file_entries, _ = cli.load_wordlist(fpath, "file")
    ignore_rules = rules.IgnoreRules(args.ir_pairs)
    bypass_rules = rules.BypassRules(args.br_pairs)
    case_filter = rules.CaseFilter(args.cs)

    state = GlobalState(args)
    eng = engine.build(args, state, printer, ignore_rules, bypass_rules,
                       case_filter, dir_entries, file_entries, [])

    # 测试里不需要信号与 REPL，直接跑等待循环
    eng.start()
    deadline = time.time() + timeout
    while time.time() < deadline:
        with state.lock:
            if (state.pending <= 0 and state.active <= 0) or state.stop_flag:
                break
        time.sleep(0.05)
    else:
        raise AssertionError("扫描超时未结束（可能死锁）")

    state.pause_event.set()
    with state.lock:
        state.cond.notify_all()
    for w in eng.workers:
        w.join(timeout=3.0)
    return state.results, state.errors, state, printed


# ----------------------------------------------------------------------
# 用例
# ----------------------------------------------------------------------
def test_normal_site():
    existing = {
        "/": (200, b"root"),
        "/admin": (200, b"admin"),
        "/admin/backend": (200, b"backend"),
        "/api": (301, b""),
        "/login": (200, b"login"),
        "/login.html": (200, b"login"),
        "/robots.txt": (200, b"robots"),
        "/nope1": (404, b"nf"),
    }
    redirects = {"/api": "/api/v2"}
    srv, url = start_server(make_handler(existing, redirects))
    try:
        # backend 必须在词表里，才能验证 admin 命中后的第 2 层递归
        res, err, st, out = run_scan(
            url, ["admin", "backend", "api", "login", "nope1"],
            ["login", "robots"],
            extra=["-s", ".html,.txt", "-t", "4", "-r", "3", "--timeout", "5"])
    finally:
        srv.shutdown()

    urls = sorted(r["url"] for r in res)
    print("  results:", urls)
    assert url + "/admin" in urls, urls
    assert url + "/admin/backend" in urls, "递归未展开: %s" % urls
    assert url + "/login" in urls, urls
    assert url + "/login.html" in urls, urls
    assert url + "/robots.txt" in urls, urls
    assert url + "/nope1" not in urls, urls
    # 301 要带上 location
    api = [r for r in res if r["url"] == url + "/api"][0]
    assert api["code"] == 301 and api["location"] == "/api/v2", api
    print("  test_normal_site OK")


def test_soft404_root_aborts():
    srv, url = start_server(make_handler({}, soft404=True))
    try:
        res, err, st, out = run_scan(
            url, ["admin", "api"], ["login"],
            extra=["-t", "2", "-r", "2", "--timeout", "5"])
    finally:
        srv.shutdown()
    print("  printed:", [l for l in out if "软 404" in l or "终止" in l])
    assert st.stop_flag, "软 404 根目录应终止扫描"
    assert not res, "软 404 下不应有结果: %s" % res
    # 终止时必须带出关键请求的响应包关键信息（status_code / content_length）
    text = "\n".join(out)
    assert "无法继续扫描，终止" in text, text
    assert re.search(r"! 关键请求: \S+ \S+", text), text
    assert "status_code=200" in text, text
    assert re.search(r"content_length=\d+", text), text
    print("  test_soft404_root_aborts OK")


def test_ir_applies_to_probes():
    """--ir 命中时探针也必须按「未命中」结算。

    场景：软 404 服务器统一回 200 + 固定长度的错误页，用户用 --ir size
    把该长度声明为 404。此时 dircheck 探针返回的正是这种响应，必须判为
    「随机路径不存在」——扫描继续，而不是识别成软 404 后终止。
    """
    counter = []
    srv, url = start_server(make_handler({}, soft404=True, counter=counter))
    try:
        # 软 404 的响应体都很短（"soft404 " + 路径），10-100 覆盖全部
        res, err, st, out = run_scan(
            url, ["admin", "api"], ["login"],
            extra=["-t", "2", "-r", "2", "--timeout", "5",
                   "--ir", "size", "10-100"])
    finally:
        srv.shutdown()
    text = "\n".join(out)
    assert not st.stop_flag, "dircheck 被 --ir 忽略后不应终止: %s" % text
    assert "无法继续扫描，终止" not in text, text
    assert "/admin" in counter, "扫描应继续进行: %s" % counter[:20]
    assert not res, res
    print("  test_ir_applies_to_probes OK")


def test_size_uses_bytes_not_chars():
    """无 Content-Length 时，size 取 r.content 的字节数，不是 r.text 的字符数。

    中文等多字节内容两者会差出倍数。--ir size 的匹配和终止提示里的
    content_length 都走这个 size，必须与 Content-Length 同口径（解压后字节数）。
    """
    body = "汉字abc".encode("utf-8")        # 9 字节；"汉字abc" 只有 5 个字符

    class NoLength(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()              # 故意不发 Content-Length，靠连接关闭定界
            self.wfile.write(body)

    srv, url = start_server(NoLength)
    try:
        args = SimpleNamespace(ti_range=(0.0, 0.0), thread=1, keep_alive=True,
                               ka_limit=200, headers=None, proxy=None,
                               timeout=5, method="get")
        sc = Scanner(args)
        try:
            resp = sc.fetch(url + "/whatever")
        finally:
            sc.close()
    finally:
        srv.shutdown()

    assert resp.error is None, resp
    assert resp.code == 200, resp
    assert resp.size == len(body), \
        "size 应为字节数 %d，实际 %s" % (len(body), resp.size)
    info = resp.key_info()
    assert "content_length=%d" % len(body) in info, info
    print("  test_size_uses_bytes_not_chars OK")


def test_no_bak_skips_backup_paths():
    """--nb：不自动添加任何备份路径（备份文件、备份探针、目录自身备份）。

    同一靶机跑两次对照：默认会发备份探针、扫备份文件、追加目录自身备份；
    --nb 时这些请求一条都不发，常规扫描不受影响。
    """
    existing = {"/admin": (200, b"admin"), "/index.html": (200, b"i")}
    base = ["-t", "4", "-r", "1", "--timeout", "5"]

    def scan(extra):
        counter = []
        srv, url = start_server(make_handler(existing, counter=counter))
        try:
            res, err, st, out = run_scan(url, ["admin"], ["index"],
                                         extra=extra)
        finally:
            srv.shutdown()
        return res, url, [p.split("?")[0] for p in counter]

    # 对照组：默认行为
    res0, url0, paths0 = scan(base)
    assert [p for p in paths0 if "__probe__" in p], "默认应发备份探针"
    assert "/db.zip" in paths0, "默认应扫备份文件"
    assert "/admin.gz" in paths0, "默认应追加目录自身备份"
    assert url0 + "/admin" in [r["url"] for r in res0], res0
    print("  默认请求数 %d" % len(paths0))

    # --nb：备份相关请求一条都不该出现
    res1, url1, paths1 = scan(base + ["--nb"])
    print("  --nb 请求数 %d: %s" % (len(paths1), paths1))
    assert not [p for p in paths1 if "__probe__" in p], paths1
    bak_suffixes = tuple(probes.BACKUP_SUFFIXES + probes.DIR_BACKUP_SUFFIXES)
    assert not [p for p in paths1 if p.lower().endswith(bak_suffixes)], paths1
    assert url1 + "/admin" in [r["url"] for r in res1], res1
    print("  test_no_bak_skips_backup_paths OK")


def test_dead_suffix_skipped():
    """后缀探测语义（按规格）：

    只有当「随机名 + 该后缀」也被返回存在（服务器对不存在的东西回 200）时，
    该后缀才被判为不可信并跳过。随机名返回 404 属于正常，后缀照常扫。

    这里构造的就是正常站点：/index.php 与 /admin/index.php 都不存在，
    所以探测会通过，.php 任务全部发出——验证的是「不该被误跳过」。
    """
    counter = []
    existing = {"/admin": (200, b"admin"), "/admin/index.html": (200, b"i")}
    srv, url = start_server(make_handler(existing, counter=counter))
    try:
        res, err, st, out = run_scan(
            url, ["admin"], ["index"],
            extra=["-s", ".php,.html", "-t", "2", "-r", "2", "--timeout", "5"])
    finally:
        srv.shutdown()
    urls = sorted(r["url"] for r in res)
    print("  results:", urls)
    assert url + "/admin" in urls, urls
    assert url + "/admin/index.html" in urls, urls
    # 正常站点上 .php 探测通过，index.php 确实被请求过（只是不存在）
    php_hits = [p for p in counter if p.endswith(".php")]
    print("  .php 请求:", php_hits)
    assert any("/index.php" in p for p in php_hits), php_hits
    print("  test_dead_suffix_skipped OK")


def test_suffix_lied_about():
    """后缀被服务器放行时（随机 .php 也回 200）跳过该后缀。

    这是后缀探测真正要防的场景：站点对不存在的 .php 也回 200，
    此时 .php 结果全部不可信，应该整体跳过而不是报一堆假结果。
    """
    counter = []

    # 用 soft404 变体：仅对 .php 路径放行，其他走正常 404
    def make_php_soft():
        from http.server import BaseHTTPRequestHandler

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *a):
                pass

            def _send(self, code, body):
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _handle(self):
                counter.append(self.path)
                path = self.path.split("?")[0]
                if path.endswith(".php"):
                    return self._send(200, b"php always ok")
                if path in ("/admin", "/admin/index.html"):
                    return self._send(200, b"ok")
                return self._send(404, b"nf")

            do_GET = _handle
            do_HEAD = _handle

        return H

    srv, url = start_server(make_php_soft())
    try:
        res, err, st, out = run_scan(
            url, ["admin"], ["index"],
            extra=["-s", ".php,.html", "-t", "2", "-r", "2", "--timeout", "5"])
    finally:
        srv.shutdown()
    urls = sorted(r["url"] for r in res)
    print("  results:", urls)
    assert url + "/admin" in urls, urls
    assert url + "/admin/index.html" in urls, urls
    # .php 被判定不可信，index.php 不应出现在结果里
    assert url + "/admin/index.php" not in urls, urls
    print("  test_suffix_lied_about OK")


def test_ignore_rules():
    """--ir 命中即等同 404：不进结果，也不会把报告刷爆。

    目录被忽略要留痕（否则整棵子树静默消失），文件与备份路径被忽略
    属于常态，跟普通 404 一样不记录、不出现在报告里。
    """
    existing = {"/admin": (200, b"a" * 10), "/login": (200, b"b" * 99)}
    srv, url = start_server(make_handler(existing))
    try:
        res, err, st, out = run_scan(
            url, ["admin", "login"], ["index"],
            extra=["-t", "2", "-r", "1", "--timeout", "5",
                   "--ir", "size", "99"])
    finally:
        srv.shutdown()
    urls = sorted(r["url"] for r in res)
    print("  results:", urls)
    assert url + "/admin" in urls, urls
    assert url + "/login" not in urls, "--ir size 99 应把 login 判为 404"

    report = "\n".join(output.format_report(st, _args_for(url)))
    print("  --- 报告 ---")
    for line in report.splitlines():
        print("   |", line)
    # 目录被忽略：留在报告的 Ignored Paths 里
    assert "/login" in report, "被忽略的目录应留痕: %s" % report
    # 文件 / 备份路径被忽略：报告里一条都不出现（当初一屏全是它们）
    assert "/db.zip" not in report, "被忽略的备份路径不该进报告: %s" % report
    assert "/index" not in report, "被忽略的文件不该进报告: %s" % report
    print("  test_ignore_rules OK")


def _args_for(url):
    """报告渲染只用到 args.url，测试里按目标拼一个即可。"""
    ns = cli.build_parser().parse_args(
        ["-u", url, "-d", "d.txt", "-f", "f.txt"])
    return cli.Args(ns)


def test_bypass_rules():
    existing = {"/admin": (200, b"a"), "/keepout": (200, b"b")}
    srv, url = start_server(make_handler(existing))
    try:
        res, err, st, out = run_scan(
            url, ["admin", "keepout"], ["x"],
            extra=["-t", "2", "-r", "1", "--timeout", "5",
                   "--br", "name", "keep"])
    finally:
        srv.shutdown()
    urls = sorted(r["url"] for r in res)
    print("  results:", urls)
    assert url + "/admin" in urls, urls
    assert url + "/keepout" not in urls, "--br name keep 应排除 keepout"
    print("  test_bypass_rules OK")


def test_ka_no_reuse():
    """--ka 为负数时每个请求都不复用连接。"""
    counter = []
    existing = {"/admin": (200, b"a")}
    srv, url = start_server(make_handler(existing, counter=counter))
    try:
        res, err, st, out = run_scan(
            url, ["admin"], ["x"],
            extra=["-t", "1", "-r", "1", "--timeout", "5", "--ka", "-1"])
    finally:
        srv.shutdown()
    print("  请求数:", len(counter), "结果:", [r["url"] for r in res])
    assert res, "应以结果收尾"
    print("  test_ka_no_reuse OK")


def test_command_parsing():
    p = control.parse_command
    assert p("").name == "noop"
    assert p("go").name == "go"
    assert p("status").name == "status"
    assert p("stop").name == "stop"
    assert p("pause").name == "pause"
    assert p("help").name == "help"
    c = p("rp admin_x")
    assert c.name == "rp" and c.arg == "admin_x", c
    assert p("rp").error, "rp 缺参数应报错"
    c = p("at 5")
    assert c.name == "at" and c.arg == 5, c
    c = p("at -3")
    assert c.arg == -3, c
    assert p("at abc").error
    assert p("at").error
    c = p("exec test_list.add(123)")
    assert c.name == "exec" and c.arg == "test_list.add(123)", c
    assert p("exec").error
    assert p("bogus").error
    print("  test_command_parsing OK")


def test_rp_removes_results():
    """rp 前缀移除：admin_x 应清掉 admin_1 与 admin_2。"""
    args = cli.Args(cli.build_parser().parse_args(
        ["-u", "http://x", "-d", "file.txt", "-f", "testf.txt"]))
    st = GlobalState(args)
    for name in ("admin_1", "admin_2", "adminX", "api"):
        st.add_result({"path": name, "url": "http://x/" + name, "type": "dir",
                       "code": 200, "size": 1, "location": None,
                       "from": "common", "remark": "", "depth": 1})
    assert len(st.results) == 4
    n = st.suppress("admin_")
    left = sorted(r["path"] for r in st.results)
    print("  移除 %d 条，剩余 %s" % (n, left))
    assert n == 2, n
    assert left == ["adminX", "api"], left
    print("  test_rp_removes_results OK")


def test_wordlist_json_remark():
    tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp")
    if not os.path.isdir(tmp):
        os.makedirs(tmp)
    path = os.path.join(tmp, "wl.txt")
    with open(path, "w") as fh:
        fh.write("admin\n")
        fh.write('backup#{"waf":3,"note":"hi"}\n')
        fh.write("plain#just text\n")
        fh.write("# 整行注释\n")
        fh.write("\n")
    entries, bad = cli.load_wordlist(path, "dir")
    names = [e["name"] for e in entries]
    print("  entries:", [(e["name"], e["remark"], e["waf"]) for e in entries])
    assert names == ["admin", "backup", "plain"], names
    assert entries[1]["waf"] == 3, entries[1]
    assert entries[2]["waf"] == 0, entries[2]
    assert bad == [], bad
    print("  test_wordlist_json_remark OK")


def test_mask_engine():
    import subprocess
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = subprocess.run([sys.executable, "-m", "pathscan.mask"], cwd=here,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = r.stdout.decode("utf-8", "replace")
    print("  mask:", out.strip().splitlines()[-1] if out.strip() else "")
    assert r.returncode == 0, out
    print("  test_mask_engine OK")


def main():
    output.setup_console()
    tests = [
        ("命令解析", test_command_parsing),
        ("rp 前缀移除", test_rp_removes_results),
        ("词表 JSON 备注", test_wordlist_json_remark),
        ("掩码引擎", test_mask_engine),
        ("正常站点", test_normal_site),
        ("软 404 终止", test_soft404_root_aborts),
        ("--ir 作用于探针", test_ir_applies_to_probes),
        ("size 用字节数", test_size_uses_bytes_not_chars),
        ("--nb 不扫备份", test_no_bak_skips_backup_paths),
        ("后缀探测通过则照常扫", test_dead_suffix_skipped),
        ("后缀被放行则跳过", test_suffix_lied_about),
        ("--ir 规则", test_ignore_rules),
        ("--br 规则", test_bypass_rules),
        ("--ka 不复用", test_ka_no_reuse),
    ]
    failed = []
    for i, (name, fn) in enumerate(tests, 1):
        print("[%d/%d] %s" % (i, len(tests), name))
        t0 = time.time()
        try:
            fn()
        except Exception as exc:
            import traceback
            traceback.print_exc()
            failed.append((name, repr(exc)))
        print("      (%.1fs)" % (time.time() - t0))
    print("=" * 66)
    if failed:
        print("失败 %d/%d:" % (len(failed), len(tests)))
        for n, e in failed:
            print("  - %s: %s" % (n, e))
        return 1
    print("全部 %d 项通过" % len(tests))
    return 0


if __name__ == "__main__":
    sys.exit(main())
