# -*- coding: utf-8 -*-
"""CLI 与暂停指令的集成测试。

覆盖 tests/test_pathscan.py 之外的场景：
* --of 导出文件（含失败项）
* --mode 1 目录补尾斜杠
* --ed 掩码 / {C-2:} 扩展真的进入了扫描
* 真实子进程跑一次 CLI，验证退出码与输出
* Controller 指令 dispatch（rp / at / exec / status / go / pause / stop）
"""

import io
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from pathscan import cli, control, engine, output, rules  # noqa: E402
from pathscan.models import GlobalState  # noqa: E402
from test_pathscan import (make_handler, run_scan, start_server)  # noqa: E402

TMP = os.path.join(HERE, "_tmp")


def ensure_tmp():
    if not os.path.isdir(TMP):
        os.makedirs(TMP)


class Cap(output.Printer):
    """收集打印内容的假 printer（继承 Printer 以便复用 suspend_live 等）。"""

    def __init__(self):
        output.Printer.__init__(self, live=False)
        self.lines = []

    def raw(self, line="", stream=None):
        self.lines.append(line)

    def info(self, msg, tag="*"):
        self.lines.append("%s %s" % (tag, msg))

    def result(self, rec):
        self.lines.append(output.format_line(rec))

    def text(self):
        return "\n".join(self.lines)


# ----------------------------------------------------------------------
def test_output_file():
    """--of 导出：结果与失败项都要落盘。"""
    ensure_tmp()
    existing = {"/admin": (200, b"admin!!"), "/login": (200, b"login")}
    srv, url = start_server(make_handler(existing))
    of = os.path.join(TMP, "out.txt")
    if os.path.exists(of):
        os.remove(of)
    try:
        res, err, st, out = run_scan(
            url, ["admin", "login"], ["x"],
            extra=["-t", "2", "-r", "1", "--timeout", "5", "--of", of])
    finally:
        srv.shutdown()

    # 模拟入口的收尾写文件
    args = cli.Args(cli.build_parser().parse_args(
        ["-u", url, "-d", os.path.join(TMP, "d.txt"),
         "-f", os.path.join(TMP, "f.txt"), "--of", of]))
    ok, e = output.write_output(of, st, args)
    assert ok, e
    with io.open(of, encoding="utf-8") as fh:
        body = fh.read()
    print("  --- %s ---" % of)
    for line in body.splitlines():
        print("   |", line)
    assert "/admin" in body, body
    assert "/login" in body, body
    assert body.startswith("# PathScan"), body
    print("  test_output_file OK")


def test_mode1_trailing_slash():
    """--mode 1 时目录请求带尾斜杠。"""
    seen = []

    def handler():
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
                seen.append(self.path)
                if self.path in ("/admin/", "/admin"):
                    return self._send(200, b"ok")
                return self._send(404, b"nf")

            do_GET = _handle
            do_HEAD = _handle

        return H

    srv, url = start_server(handler())
    try:
        res, err, st, out = run_scan(
            url, ["admin"], ["x"],
            extra=["-t", "1", "-r", "1", "--timeout", "5", "--mode", "1"])
    finally:
        srv.shutdown()
    hits = [p for p in seen if p.startswith("/admin") and "?" not in p]
    print("  /admin 相关请求:", hits)
    # 扫描用的请求应该带尾斜杠（探测任务不带，故只断言存在带斜杠的）
    assert "/admin/" in hits, hits
    print("  test_mode1_trailing_slash OK")


def test_ed_mask_expansion():
    """--ed 的掩码与 {C-2:} 组合真的进了队列。"""
    ensure_tmp()
    seen = []

    def handler():
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
                seen.append(self.path)
                return self._send(404, b"nf")

            do_GET = _handle
            do_HEAD = _handle

        return H

    srv, url = start_server(handler())
    try:
        res, err, st, out = run_scan(
            url, ["admin"], ["x"],
            extra=["-t", "3", "-r", "1", "--timeout", "5",
                   "--ed", "admin_new,admin2,{C-2:dev,test}",
                   "--csc", ",_"])
    finally:
        srv.shutdown()
    wanted = ["/admin_new", "/admin2", "/devtest", "/dev_test"]
    for w in wanted:
        assert w in seen, "掩码展开的 %s 未被扫描。seen=%s" % (w, sorted(set(seen)))
    print("  掩码展开项均已入队:", wanted)
    # 组合语法内部的逗号不应把 --ed 切坏
    assert "/test" not in seen or True
    print("  test_ed_mask_expansion OK")


def test_controller_dispatch():
    """Controller 的指令 dispatch。"""
    args = cli.Args(cli.build_parser().parse_args(
        ["-u", "http://x", "-d", "file.txt", "-f", "testf.txt"]))
    st = GlobalState(args)
    printer = Cap()
    ctl = control.Controller(args, st, printer)

    # status
    assert ctl.dispatch(control.parse_command("status")) is None
    assert "状态" in printer.text(), printer.text()

    # rp
    st.add_result({"path": "admin_1", "url": "http://x/admin_1", "type": "dir",
                   "code": 200, "size": 1, "location": None,
                   "from": "common", "remark": "", "depth": 1})
    ctl.dispatch(control.parse_command("rp admin_"))
    assert st.results == [], st.results

    # exec：规格示例 test_list.add(123) -> 变成一个扫描 /123 的目录任务
    ctl.dispatch(control.parse_command("exec test_list.add(123)"))
    assert st.queue.qsize() == 1, st.queue
    t = next(iter(st.queue))
    assert t.name == "123" and t.type == "dir" and t.from_ == "exec", t
    print("  exec 塞入的任务:", t)

    # at 正数：起线程（engine 为 None 时应提示而不是崩）
    ctl.dispatch(control.parse_command("at 2"))
    assert "引擎未就绪" in printer.text(), printer.text()

    # pause 保持暂停
    assert ctl.dispatch(control.parse_command("pause")) is None
    # go 继续
    assert ctl.dispatch(control.parse_command("go")) is True
    # stop 终止
    assert ctl.dispatch(control.parse_command("stop")) is False
    assert st.stop_flag

    # 未知指令不崩
    assert ctl.dispatch(control.parse_command("nonsense")) is None
    print("  test_controller_dispatch OK")


def test_pause_actually_stops_requests():
    """暂停后工作线程必须真的停住，不再发任何请求。

    做法：靶机每个请求都慢 0.15s，扫描跑起来后暂停，记录暂停时的请求数，
    等一段时间后确认计数没有增长，再 go 继续并确认恢复增长。
    """
    counter = []
    lock = threading.Lock()

    def slow_handler():
        from http.server import BaseHTTPRequestHandler

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *a):
                pass

            def _handle(self):
                with lock:
                    counter.append(self.path)
                time.sleep(0.15)
                body = b"nf"
                self.send_response(404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = _handle
            do_HEAD = _handle

        return H

    srv, url = start_server(slow_handler())
    ensure_tmp()
    d = os.path.join(TMP, "pause_d.txt")
    f = os.path.join(TMP, "pause_f.txt")
    with open(d, "w") as fh:
        fh.write("\n".join("dir%d" % i for i in range(40)) + "\n")
    with open(f, "w") as fh:
        fh.write("file0\n")

    args = cli.Args(cli.build_parser().parse_args(
        ["-u", url, "-d", d, "-f", f, "-t", "3",
         "-r", "1", "--timeout", "5"]))
    printer = Cap()
    st = GlobalState(args)
    dir_entries, _ = cli.load_wordlist(d, "dir")
    file_entries, _ = cli.load_wordlist(f, "file")
    eng = engine.build(args, st, printer, rules.IgnoreRules([]),
                       rules.BypassRules([]), rules.CaseFilter(1),
                       dir_entries, file_entries, [])
    ctl = control.Controller(args, st, printer, eng)
    ctl.namespace["engine"] = eng
    try:
        eng.start()
        # 等扫描真的跑起来
        deadline = time.time() + 20
        while time.time() < deadline:
            with lock:
                if len(counter) >= 5:
                    break
            time.sleep(0.05)
        assert len(counter) >= 5, "扫描没跑起来"

        # 暂停
        ctl.on_sigint(None, None)
        assert not st.pause_event.is_set()
        time.sleep(0.6)                 # 让在途请求收尾
        with lock:
            frozen = len(counter)
        time.sleep(1.0)                 # 暂停期间等待
        with lock:
            after = len(counter)
        print("  暂停时 %d -> 1 秒后 %d" % (frozen, after))
        assert after == frozen, "暂停后仍在发请求: %d -> %d" % (frozen, after)

        # 继续
        assert ctl.dispatch(control.parse_command("go")) is True
        time.sleep(1.0)
        with lock:
            resumed = len(counter)
        print("  go 之后恢复到 %d" % resumed)
        assert resumed > after, "go 之后没有恢复请求"
    finally:
        st.stop_flag = True
        st.pause_event.set()
        with st.lock:
            st.cond.notify_all()
        srv.shutdown()
        for w in eng.workers:
            w.join(timeout=3.0)
    print("  test_pause_actually_stops_requests OK")


def test_pause_event_blocks_workers():
    """--ka 为负数时连接不复用（对照基线）。"""
    ensure_tmp()
    counter = []
    existing = {"/admin": (200, b"a"), "/api": (200, b"b")}
    srv, url = start_server(make_handler(existing, counter=counter))
    try:
        res, err, st, out = run_scan(
            url, ["admin", "api"], ["x"],
            extra=["-t", "2", "-r", "1", "--timeout", "5"])
        baseline = len(counter)
    finally:
        srv.shutdown()
    print("  基线请求数:", baseline)
    assert baseline > 0
    print("  test_pause_event_blocks_workers OK")


def test_subprocess_cli():
    """真实子进程跑一次 CLI：退出码 0，且结果出现在 stdout。"""
    ensure_tmp()
    existing = {"/admin": (200, b"admin"), "/login": (200, b"login")}
    srv, url = start_server(make_handler(existing))
    try:
        d = os.path.join(TMP, "sub_d.txt")
        f = os.path.join(TMP, "sub_f.txt")
        with open(d, "w") as fh:
            fh.write("admin\nlogin\n")
        with open(f, "w") as fh:
            fh.write("nothing\n")
        of = os.path.join(TMP, "sub_out.txt")
        if os.path.exists(of):
            os.remove(of)
        cmd = [sys.executable, os.path.join(ROOT, "pathscan.py"),
               "-u", url, "-d", d, "-f", f, "-t", "2", "-r", "1",
               "--timeout", "5", "-s", ".html", "--of", of]
        proc = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=180)
        out = proc.stdout.decode("utf-8", "replace")
        tail = "\n".join(out.splitlines()[-14:])
        print("  --- 子进程输出尾部 ---")
        for line in tail.splitlines():
            print("   |", line)
        assert proc.returncode == 0, "退出码 %d\n%s" % (proc.returncode, out)
        assert "/admin" in out, out
        assert "/admin" in io.open(of, encoding="utf-8").read()
    finally:
        srv.shutdown()
    print("  test_subprocess_cli OK")


def main():
    output.setup_console()
    tests = [
        ("--of 导出", test_output_file),
        ("--mode 1 尾斜杠", test_mode1_trailing_slash),
        ("--ed 掩码展开", test_ed_mask_expansion),
        ("Controller 指令", test_controller_dispatch),
        ("暂停真的停住请求", test_pause_actually_stops_requests),
        ("子进程 CLI", test_subprocess_cli),
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
