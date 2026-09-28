# -*- coding: utf-8 -*-
"""WAF 自动检测、线程健康度、速度统计的测试。"""

import io
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from pathscan import cli, control, engine, models, output, rules  # noqa: E402
from pathscan.models import GlobalState  # noqa: E402
from test_pathscan import make_handler, run_scan, start_server  # noqa: E402


class Cap(output.Printer):
    """收集输出的假 printer。"""

    def __init__(self):
        output.Printer.__init__(self, live=False)
        self.lines = []

    def raw(self, line="", stream=None):
        self.lines.append(line)

    def info(self, msg, tag="*"):
        self.lines.append("%s %s" % (tag, msg))

    def text(self):
        return "\n".join(self.lines)


def mk_args(extra=None):
    argv = ["-u", "http://x", "-d", "testd.txt", "-f", "testf.txt"]
    return cli.Args(cli.build_parser().parse_args(argv + (extra or [])))


def mk_task(name="admin", parent="", type_="dir"):
    from pathscan.models import Task
    return Task(type=type_, name=name, parent=parent)


# ----------------------------------------------------------------------
def test_speed_window():
    """速度 = 10 秒窗口内请求数 / 10。"""
    st = GlobalState(mk_args())
    assert st.speed() == 0.0, "初始速度应为 0"

    for _ in range(100):
        st.record_request()
    s = st.speed()
    print("  100 次请求 -> %.1f/s" % s)
    assert abs(s - 10.0) < 0.01, s

    # 桶会随秒数推进，模拟时间流逝后窗口应清空
    st.req_last_sec -= (models.SPEED_WINDOW + 5)
    print("  时间推进后 -> %.1f/s" % st.speed())
    assert st.speed() == 0.0, "窗口过期后速度应归零"
    print("  test_speed_window OK")


def test_waf_single_name_blocked():
    """窗口内只有自己 -> 加入忽略列表。"""
    st = GlobalState(mk_args())
    now = 1000.0
    assert st.waf_note_fail("admin", now)
    # 同一个 name 不重复登记
    assert not st.waf_note_fail("admin", now + 1)

    blocked, dropped = st.waf_collect_due(now + models.WAF_WINDOW_SECONDS)
    print("  blocked=%s dropped=%s" % (blocked, dropped))
    assert blocked == ["admin"] and dropped == [], (blocked, dropped)
    assert st.is_name_bypassed("admin")
    assert st.waf_ignored == ["admin"]
    print("  test_waf_single_name_blocked OK")


def test_waf_shared_blame_removed():
    """窗口内还有别的项 -> 只移除自己，不拉黑。"""
    st = GlobalState(mk_args())
    now = 1000.0
    st.waf_note_fail("admin", now)
    st.waf_note_fail("login", now + 1.0)     # 窗口内又来一个

    blocked, dropped = st.waf_collect_due(now + models.WAF_WINDOW_SECONDS)
    print("  blocked=%s dropped=%s" % (blocked, dropped))
    assert blocked == [] and dropped == ["admin"], (blocked, dropped)
    assert not st.is_name_bypassed("admin")
    print("  test_waf_shared_blame_removed OK")


def test_waf_not_due_early():
    """未到窗口时长不结算。"""
    st = GlobalState(mk_args())
    now = 1000.0
    st.waf_note_fail("admin", now)
    blocked, dropped = st.waf_collect_due(now + 1.0)
    print("  2 秒时 blocked=%s dropped=%s" % (blocked, dropped))
    assert blocked == [] and dropped == [], (blocked, dropped)
    print("  test_waf_not_due_early OK")


def test_waf_bypass_filters_tasks():
    """被拉黑的 name 后续不再入队。"""
    st = GlobalState(mk_args())
    st.waf_note_fail("admin", 1000.0)
    st.waf_collect_due(1000.0 + models.WAF_WINDOW_SECONDS)
    assert st.is_name_bypassed("admin")

    eng = engine.build(mk_args(), st, Cap(), rules.IgnoreRules([]),
                       rules.BypassRules([]), rules.CaseFilter(1), [], [], [])
    n = eng.add_tasks([mk_task("admin"), mk_task("api")])
    names = sorted(t.name for t in st.queue)
    print("  入队 %d 个: %s" % (n, names))
    assert n == 1 and names == ["api"], names
    print("  test_waf_bypass_filters_tasks OK")


def test_waf_watch_needs_threshold():
    """失败次数达到阈值才纳入观察。"""
    st = GlobalState(mk_args())
    eng = engine.build(mk_args(), st, Cap(), rules.IgnoreRules([]),
                       rules.BypassRules([]), rules.CaseFilter(1), [], [], [])
    t = mk_task("admin")
    t.trytimes = models.WAF_FAIL_THRESHOLD - 1
    eng.waf_watch(t)
    assert not st.waf_window, "未到阈值不应登记: %s" % st.waf_window
    t.trytimes = models.WAF_FAIL_THRESHOLD
    eng.waf_watch(t)
    print("  达到阈值后观察窗口: %s" % list(st.waf_window))
    assert "admin" in st.waf_window
    print("  test_waf_watch_needs_threshold OK")


def test_thread_health_counters():
    """连续失败计数与成功清零。"""
    st = GlobalState(mk_args())
    for tid in (0, 1):
        st.thread_register(tid)
    assert [st.thread_fail(0) for _ in range(3)] == [1, 2, 3]
    st.thread_success(0)
    print("  成功后计数: %d" % st.thread_fail_count(0))
    assert st.thread_fail_count(0) == 0
    print("  test_thread_health_counters OK")


def test_all_other_threads_idle():
    """其他线程是否都在惩罚暂停。"""
    st = GlobalState(mk_args())
    for tid in (0, 1, 2):
        st.thread_register(tid)
    assert not st.all_other_threads_idle(0), "没人暂停时不该为 True"
    st.thread_pause(1)
    st.thread_pause(2)
    print("  其他都在暂停:", st.all_other_threads_idle(0))
    assert st.all_other_threads_idle(0)
    st.thread_resume(1)
    print("  1 号恢复后:", st.all_other_threads_idle(0))
    assert not st.all_other_threads_idle(0)
    print("  test_all_other_threads_idle OK")


def test_all_other_threads_healthy():
    """其他线程是否都健康（失败计数为 0）。"""
    st = GlobalState(mk_args())
    for tid in (0, 1, 2):
        st.thread_register(tid)
    assert st.all_other_threads_healthy(0)
    st.thread_fail(1)
    print("  1 号失败一次后:", st.all_other_threads_healthy(0))
    assert not st.all_other_threads_healthy(0)
    print("  test_all_other_threads_healthy OK")


def test_thread_penalty_pauses():
    """连续失败超过上限时线程会暂停（用短惩罚时长验证）。"""
    st = GlobalState(mk_args())
    eng = engine.build(st and mk_args(), st, Cap(), rules.IgnoreRules([]),
                       rules.BypassRules([]), rules.CaseFilter(1), [], [], [])
    w = engine.Worker(eng, 0)
    st.thread_register(0)

    orig_pause = models.THREAD_FAIL_PAUSE
    models.THREAD_FAIL_PAUSE = 0.3          # monkeypatch：只在 engine 里读
    engine.THREAD_FAIL_PAUSE = 0.3
    try:
        # 前 4 次失败不该触发暂停
        for i in range(models.THREAD_FAIL_LIMIT - 1):
            w.note_request_result(False)
        print("  %d 次失败后仍在跑" % (models.THREAD_FAIL_LIMIT - 1))
        assert w.thread_id not in st.thread_paused

        # 第 5 次触发惩罚暂停
        t0 = time.time()
        w.note_request_result(False)
        el = time.time() - t0
        print("  第 %d 次失败触发惩罚，耗时 %.2fs"
              % (models.THREAD_FAIL_LIMIT, el))
        assert el >= 0.25, "应真的等待惩罚时长: %.2f" % el
        # 惩罚结束后应已恢复
        assert w.thread_id not in st.thread_paused
    finally:
        models.THREAD_FAIL_PAUSE = orig_pause
        engine.THREAD_FAIL_PAUSE = orig_pause
    print("  test_thread_penalty_pauses OK")


def test_waf_wait_auto_resume():
    """WAF 等待模式：无按键 -> 自动恢复扫描。"""
    st = GlobalState(mk_args())
    st.pause_event.set()
    pr = Cap()
    ctl = control.Controller(mk_args(), st, pr)
    ctl._make_key_reader = lambda: None      # 永无按键

    orig = models.WAF_IDLE_RESUME
    models.WAF_IDLE_RESUME = 0.5
    try:
        t0 = time.time()
        ctl.enter_waf_wait()
        el = time.time() - t0
    finally:
        models.WAF_IDLE_RESUME = orig

    print("  耗时 %.2fs pause_event=%s" % (el, st.pause_event.is_set()))
    assert st.pause_event.is_set(), "无人值守应自动恢复"
    assert not st.waf_waiting
    assert "无人值守" in pr.text(), pr.text()
    print("  test_waf_wait_auto_resume OK")


def test_waf_wait_keypress_goes_repl():
    """WAF 等待模式：有按键 -> 进指令模式。"""
    st = GlobalState(mk_args())
    st.pause_event.set()
    pr = Cap()
    ctl = control.Controller(mk_args(), st, pr)
    ctl._make_key_reader = lambda: (lambda: True)   # 立刻有按键
    called = []
    ctl.repl = lambda: (called.append(1), True)[1]

    ctl.enter_waf_wait()
    print("  repl 调用次数:", len(called))
    assert called == [1], called
    assert "检测到输入" in pr.text(), pr.text()
    print("  test_waf_wait_keypress_goes_repl OK")


def test_waf_wait_pauses_requests():
    """WAF 等待模式期间不发出请求，恢复后继续。"""
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
                time.sleep(0.1)
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
    tmp = os.path.join(HERE, "_tmp")
    if not os.path.isdir(tmp):
        os.makedirs(tmp)
    d = os.path.join(tmp, "waf_d.txt")
    f = os.path.join(tmp, "waf_f.txt")
    with open(d, "w") as fh:
        fh.write("\n".join("dir%d" % i for i in range(60)) + "\n")
    with open(f, "w") as fh:
        fh.write("x\n")

    args = cli.Args(cli.build_parser().parse_args(
        ["-u", url, "-d", d, "-f", f, "-t", "2", "-r", "1", "--timeout", "5"]))
    pr = Cap()
    st = GlobalState(args)
    de, _ = cli.load_wordlist(d, "dir")
    fe, _ = cli.load_wordlist(f, "file")
    eng = engine.build(args, st, pr, rules.IgnoreRules([]),
                       rules.BypassRules([]), rules.CaseFilter(1), de, fe, [])
    ctl = control.Controller(args, st, pr, eng)
    try:
        eng.start()
        deadline = time.time() + 20
        while time.time() < deadline:
            with lock:
                if len(counter) >= 4:
                    break
            time.sleep(0.05)
        assert len(counter) >= 4, "扫描没跑起来"

        # 手动进入 WAF 等待（不等待自动恢复）
        st.pause_event.clear()
        time.sleep(0.6)
        with lock:
            frozen = len(counter)
        time.sleep(1.0)
        with lock:
            after = len(counter)
        print("  WAF 等待中 %d -> 1 秒后 %d" % (frozen, after))
        assert after == frozen, "WAF 等待期间不应发请求: %d -> %d" % (frozen, after)

        # 恢复
        st.pause_event.set()
        with st.lock:
            st.cond.notify_all()
        time.sleep(1.0)
        with lock:
            resumed = len(counter)
        print("  恢复后 %d" % resumed)
        assert resumed > after, "恢复后应继续请求"
    finally:
        st.stop_flag = True
        st.pause_event.set()
        with st.lock:
            st.cond.notify_all()
        srv.shutdown()
        for w in eng.workers:
            w.join(timeout=3.0)
    print("  test_waf_wait_pauses_requests OK")


def test_live_log_has_speed_not_in_report():
    """实时日志带 Speed，报告与导出不含 Speed。"""
    import io

    st = GlobalState(mk_args())
    for _ in range(50):
        st.record_request()
    sp = st.speed()

    # live_line 走的是 Printer 自己的 stream，这里用假 TTY 捕获
    class FakeTTY(io.StringIO):
        def isatty(self):
            return True

    buf = FakeTTY()
    pr = output.Printer(live=True, stream=buf)
    pr.live_line(0, "admin", True, speed=sp)
    pr.live_line(1, "nope", False, speed=sp)
    pr.finish_live()
    text = buf.getvalue()
    print("  实时行:", text.replace("\r", "<CR>").splitlines())
    assert "Speed:" in text, text
    assert "/s" in text, text

    st.add_result({"path": "admin", "url": "http://t/admin", "type": "dir",
                   "code": 200, "size": 10, "location": None,
                   "from": "common", "remark": "", "depth": 1})
    report = "\n".join(output.format_report(st, mk_args()))
    print("  --- 报告 ---")
    for line in report.splitlines():
        print("   |", line)
    assert "Speed" not in report, "报告不应含 Speed"
    assert "ThreadID" not in report, "报告不应含实时日志"

    # 导出到文件同样不含
    args = mk_args()
    of = os.path.join(HERE, "_tmp", "waf_out.txt")
    if not os.path.isdir(os.path.dirname(of)):
        os.makedirs(os.path.dirname(of))
    ok, err = output.write_output(of, st, args)
    assert ok, err
    body = io.open(of, encoding="utf-8").read()
    assert "Speed" not in body and "ThreadID" not in body, body
    print("  test_live_log_has_speed_not_in_report OK")


def test_ip_backup_names_no_permutations():
    """IP 目标：保留完整 IP 的四种写法，不做子集排列组合。"""
    from pathscan import probes

    for host, expect in (
            ("127.0.0.1", ["127.0.0.1", "127001", "127_0_0_1", "127-0-0-1"]),
            ("192.168.81.135",
             ["192.168.81.135", "19216881135",
              "192_168_81_135", "192-168-81-135"])):
        names = probes.build_backup_names(host)
        missing = [w for w in expect if w not in names]
        print("  %s: 共 %d 个，四种写法缺失 %s" % (host, len(names), missing))
        assert not missing, missing

    # 不再生成子集排列组合
    names = probes.build_backup_names("192.168.81.135")
    for bad in ("81.135", "0-0-1", "192-168", "168_81", "135.192"):
        assert bad not in names, "不该生成 %s" % bad
    print("  已确认无子集排列组合")

    # 域名仍然做组合
    dom = probes.build_backup_names("abc.google.com")
    assert any("google" in n for n in dom), dom
    assert len(dom) > len(probes.BACKUP_NAMES), "域名应有派生名"
    print("  域名派生仍保留: %d 个" % len(dom))

    # IP 的备份任务量应显著小于域名
    ip_tasks = len(probes.build_backup_names("192.168.81.135"))
    print("  IP 备份名 %d × %d 后缀 = %d 任务"
          % (ip_tasks, len(probes.BACKUP_SUFFIXES),
             ip_tasks * len(probes.BACKUP_SUFFIXES)))
    print("  test_ip_backup_names_no_permutations OK")


def test_live_path_alignment():
    """路径不足 LIVE_PATH_WIDTH 补齐对齐，超长原样输出。"""
    import io
    import re

    class FakeTTY(io.StringIO):
        def isatty(self):
            return True

    width = output.LIVE_PATH_WIDTH
    buf = FakeTTY()
    pr = output.Printer(live=True, stream=buf)
    pr.live_line(0, "a", False, speed=1.0)                 # 很短
    pr.live_line(1, "b" * (width - 1), True, speed=2.0)    # 正好
    pr.live_line(2, "c" * (width + 20), False, speed=3.0)  # 超长
    pr.finish_live()

    rows = [r for r in buf.getvalue().split("\r") if r.strip()]
    marks = []
    for row in rows:
        # [ok ] 补了一个空格与 [err] 等长，所以这里允许标记内出现空格
        m = re.search(r"\[(ok |err)\]", row)
        assert m, row
        marks.append(m.start())
    print("  状态标记起始列: %s" % marks)
    # 前两条（短、正好）必须对齐；超长那条允许不对齐
    assert marks[0] == marks[1], marks
    assert marks[2] > marks[1], "超长路径应在更右侧: %s" % marks

    # [ok ] 与 [err] 的标记长度必须一致，否则后面的 Speed 会对不齐
    assert len("[ok ]") == len("[err]")
    ok_rows = [r for r in rows if "[ok ]" in r]
    err_rows = [r for r in rows if "[err]" in r]
    assert ok_rows and err_rows, rows
    print("  OK/ERR 标记等长: [ok ] / [err]")
    print("  test_live_path_alignment OK")


def test_ctrl_c_starts_new_line():
    """Ctrl+C 提示必须另起新行，不与实时日志连续。"""
    import io

    class FakeTTY(io.StringIO):
        def isatty(self):
            return True

    buf = FakeTTY()
    pr = output.Printer(live=True, stream=buf)
    args = mk_args()
    st = GlobalState(args)

    pr.live_line(0, "nope1", False, speed=10.0)   # 留下未换行的临时行
    ctl = control.Controller(args, st, pr)
    ctl.on_sigint(None, None)

    raw = buf.getvalue()
    print("  原始片段: %r" % raw[:90])
    # 暂停提示之前必须是换行，不能直接接在日志后面
    idx = raw.find("====")
    assert idx > 0, raw
    assert raw[idx - 1] == "\n", "提示前应是换行，实际 %r" % raw[idx - 2:idx]
    assert "\n\n" not in raw, "不应出现多余空行"
    assert st.pause_requested and not st.pause_event.is_set()
    print("  test_ctrl_c_starts_new_line OK")


def test_ctrl_c_twice_stops():
    """暂停中再按 Ctrl+C 直接退出。"""
    import io

    class FakeTTY(io.StringIO):
        def isatty(self):
            return True

    buf = FakeTTY()
    pr = output.Printer(live=True, stream=buf)
    args = mk_args()
    st = GlobalState(args)
    ctl = control.Controller(args, st, pr)

    pr.live_line(0, "x", False, speed=1.0)
    ctl.on_sigint(None, None)
    assert not st.stop_flag
    pr.live_line(0, "y", False, speed=1.0)
    ctl.on_sigint(None, None)
    print("  stop_flag=%s" % st.stop_flag)
    assert st.stop_flag
    assert "再次中断" in buf.getvalue()
    print("  test_ctrl_c_twice_stops OK")


def test_depth_range_parse():
    """备注里的 r 字段解析：0-1 / 2 / 1- 三种写法。"""
    assert cli.parse_depth_range(None) == (0, None)
    assert cli.parse_depth_range("") == (0, None)
    assert cli.parse_depth_range("0-1") == (0, 1)
    assert cli.parse_depth_range("2") == (2, 2)
    assert cli.parse_depth_range("1-") == (1, None)
    print("  0-1 -> %s   2 -> %s   1- -> %s"
          % (cli.parse_depth_range("0-1"), cli.parse_depth_range("2"),
             cli.parse_depth_range("1-")))
    for bad in ("x-y", "5-2"):
        try:
            cli.parse_depth_range(bad)
            raise AssertionError("应报错: %s" % bad)
        except ValueError:
            pass
    print("  test_depth_range_parse OK")


def test_depth_allowed_semantics():
    """r=0-1 表示 /test 测、/xx/test 不测。"""
    from pathscan.models import Task

    # 第 1 层（根目录下）应通过
    t = Task("dir", "test", "", depth_lo=0, depth_hi=1)
    print("  /test      path_depth=%d allowed=%s" % (t.path_depth,
                                                    t.depth_allowed()))
    assert t.depth_allowed()

    # 第 2 层（/admin/test）应被拦下
    t2 = Task("dir", "test", "admin", depth_lo=0, depth_hi=1)
    print("  /admin/test path_depth=%d allowed=%s" % (t2.path_depth,
                                                     t2.depth_allowed()))
    assert not t2.depth_allowed(), "第 2 层必须被拦下"

    # 第 3 层
    t3 = Task("dir", "test", "a/b", depth_lo=0, depth_hi=1)
    assert not t3.depth_allowed(), "第 3 层必须被拦下"

    # 无限制一律通过
    assert Task("dir", "x", "a/b/c").depth_allowed()
    # 下限
    assert not Task("dir", "x", "", depth_lo=2).depth_allowed()
    assert Task("dir", "x", "admin", depth_lo=2).depth_allowed()
    print("  test_depth_allowed_semantics OK")


def test_remark_field_parsing():
    """备注 JSON：remark 原样保留（值本身无特殊含义）；与 waf/r 共存。"""
    import tempfile

    tmp = tempfile.mkdtemp()
    p = os.path.join(tmp, "w.txt")
    with io.open(p, "w", encoding="utf-8") as fh:
        fh.write(u"admin\n")
        fh.write(u'tagged#{"remark":"ZhiyuanOA"}\n')
        fh.write(u'as404#{"remark":"404"}\n')
        fh.write(u'mix#{"remark":"后台","waf":3,"r":"0-2"}\n')
        fh.write(u'onlyr#{"r":"1-"}\n')
    entries, bad = cli.load_wordlist(p, "dir")
    assert not bad, bad
    by = {e["name"]: e for e in entries}

    print("  tagged remark=%r" % by["tagged"]["remark"])
    assert by["tagged"]["remark"] == "ZhiyuanOA"
    # remark 的值就是普通文本，"404" 没有特殊含义
    print("  as404  remark=%r (原样保留)" % by["as404"]["remark"])
    assert by["as404"]["remark"] == "404", "remark 值应原样保留"
    m = by["mix"]
    print("  mix    remark=%r waf=%s r=(%s,%s)"
          % (m["remark"], m["waf"], m["depth_lo"], m["depth_hi"]))
    assert m["remark"] == u"后台" and m["waf"] == 3
    assert (m["depth_lo"], m["depth_hi"]) == (0, 2)
    assert (by["onlyr"]["depth_lo"], by["onlyr"]["depth_hi"]) == (1, None)
    assert by["admin"]["remark"] == ""
    print("  test_remark_field_parsing OK")


def test_remark_shown_only_on_non_404():
    """备注只在请求非 404 时显示（与备注的值无关）。"""
    import io as _io

    class FakeTTY(_io.StringIO):
        def isatty(self):
            return True

    # 命中（非 404）-> 显示备注
    buf = FakeTTY()
    pr = output.Printer(live=True, stream=buf)
    pr.live_line(0, "admin", True, speed=1.0, remark="ZhiyuanOA")
    pr.finish_live()
    text = buf.getvalue()
    print("  [ok ] 行:", text.strip())
    assert "#ZhiyuanOA" in text, text

    # 404（ok=False）-> 不显示备注
    buf2 = FakeTTY()
    pr2 = output.Printer(live=True, stream=buf2)
    pr2.live_line(0, "admin", False, speed=1.0, remark="ZhiyuanOA")
    pr2.finish_live()
    print("  [err] 行:", buf2.getvalue().strip())
    assert "ZhiyuanOA" not in buf2.getvalue(), buf2.getvalue()

    # 备注为空时也不出现多余的 #
    buf3 = FakeTTY()
    pr3 = output.Printer(live=True, stream=buf3)
    pr3.live_line(0, "admin", True, speed=1.0, remark="")
    pr3.finish_live()
    assert "#" not in buf3.getvalue(), buf3.getvalue()

    # 最终报告：备注只在 Result(OK)，不在 Ignored Paths
    st = GlobalState(mk_args())
    st.add_result({"path": "admin", "url": "http://t/admin", "type": "dir",
                   "code": 200, "size": 10, "location": None,
                   "from": "common", "remark": "ZhiyuanOA", "depth": 1})
    st.add_ignored(mk_task("ignored1"), "http://t/ignored1", 301, 0,
                   "/x", "--ir test")
    st.ignored[-1]["remark"] = "不该出现"
    report = "\n".join(output.format_report(st, mk_args()))
    print("  --- 报告 ---")
    for line in report.splitlines():
        print("   |", line)
    assert "#ZhiyuanOA" in report, report
    assert "不该出现" not in report, "Ignored Paths 不应显示备注"
    print("  test_remark_shown_only_on_non_404 OK")


def test_error_shows_demos():
    """参数出错与 --help 都带常用命令示例。"""
    demos = cli.format_demos()
    for label in ("Common IIS", "Common JSP", "Common PHP",
                  "Full   IIS", "Full   JSP"):
        assert label in demos, label
    assert ".aspx" in demos and ".jsp" in demos and ".php" in demos
    assert "--cs1 ?h?H" in demos and "--cs1 ?h" in demos
    print("  demos 行数:", len(demos.splitlines()))
    for line in demos.splitlines():
        print("   |", line)

    # --help 的 epilog 里也要有
    helptext = cli.build_parser().format_help()
    assert "Common Commands" in helptext, helptext[-400:]
    assert "Common IIS" in helptext
    print("  --help 含示例: OK")

    # 参数错误时 stderr 里也要有
    import subprocess
    proc = subprocess.run([sys.executable, os.path.join(ROOT, "pathscan.py"),
                           "-u", "http://x"],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = proc.stdout.decode("utf-8", "replace")
    assert proc.returncode == 2, proc.returncode
    assert "Common IIS" in out, out[-400:]
    assert "error:" in out
    print("  参数缺失时退出码 %d 且含示例: OK" % proc.returncode)
    print("  test_error_shows_demos OK")


def test_ok_dirs_parsing():
    """--od 逐层展开，支持多次传入与逗号分隔，去重保序。"""
    assert cli.parse_ok_dirs(["dir1/dir2/dir3/"]) == [
        "dir1", "dir1/dir2", "dir1/dir2/dir3"]
    assert cli.parse_ok_dirs(["dir1/dir2/dir3"]) == [
        "dir1", "dir1/dir2", "dir1/dir2/dir3"]
    assert cli.parse_ok_dirs(["admin"]) == ["admin"]
    # 逗号分隔 + 多次传入
    assert cli.parse_ok_dirs(["a/b,c"]) == ["a", "a/b", "c"]
    assert cli.parse_ok_dirs(["x/y", "z"]) == ["x", "x/y", "z"]
    # 去重且保持由浅到深
    assert cli.parse_ok_dirs(["a/b,a/b/c", "a"]) == ["a", "a/b", "a/b/c"]
    # 首尾斜杠与空值
    assert cli.parse_ok_dirs(["/a/"]) == ["a"]
    assert cli.parse_ok_dirs([]) == []
    assert cli.parse_ok_dirs([None, "", "  "]) == []
    print("  dir1/dir2/dir3/ -> %s" % cli.parse_ok_dirs(["dir1/dir2/dir3/"]))
    print("  test_ok_dirs_parsing OK")


def test_ok_dirs_skips_probe_and_recurses():
    """--od 目录不探测、直接登记结果，并参与递归。"""
    counter = []
    existing = {
        "/admin": (200, b"admin"),
        "/admin/backend": (200, b"backend"),
        "/admin/backend/users": (200, b"users"),
    }
    srv, url = start_server(make_handler(existing, counter=counter))
    tmp = os.path.join(HERE, "_tmp")
    if not os.path.isdir(tmp):
        os.makedirs(tmp)
    d = os.path.join(tmp, "od_d.txt")
    f = os.path.join(tmp, "od_f.txt")
    with open(d, "w") as fh:
        fh.write("users\n")          # 词表里只有 users
    with open(f, "w") as fh:
        fh.write("x\n")

    args = cli.Args(cli.build_parser().parse_args(
        ["-u", url, "-d", d, "-f", f, "-t", "4", "-r", "3", "--timeout", "5",
         "--od", "admin/backend/"]))
    print("  ok_dirs: %s" % args.ok_dirs)
    assert args.ok_dirs == ["admin", "admin/backend"]

    de, _ = cli.load_wordlist(d, "dir")
    fe, _ = cli.load_wordlist(f, "file")
    printer = Cap()
    st = GlobalState(args)
    eng = engine.build(args, st, printer, rules.IgnoreRules([]),
                       rules.BypassRules([]), rules.CaseFilter(1), de, fe, [])
    try:
        eng.start()
        deadline = time.time() + 60
        while time.time() < deadline:
            with st.lock:
                if (st.pending <= 0 and st.active <= 0) or st.stop_flag:
                    break
            time.sleep(0.05)
    finally:
        st.pause_event.set()
        with st.lock:
            st.cond.notify_all()
        for w in eng.workers:
            w.join(timeout=3.0)
        srv.shutdown()

    by = {r["path"]: r for r in st.results}
    print("  结果: %s" % sorted(by))
    # --od 目录只是递归种子，不写进结果（避免抢在真实扫描前面）
    assert "admin" not in by, "admin 未在靶机上，不该出现在结果里"
    # 两层都被打开参与递归
    assert "admin" in st.opened and "admin/backend" in st.opened, st.opened
    # 递归走到了第 3 层
    assert "admin/backend/users" in by, sorted(by)
    assert by["admin/backend/users"]["from"] == "common"
    print("  递归找到 admin/backend/users: OK")

    # --od 目录不该出现 dircheck 探测请求（随机名.随机后缀）
    import re
    od_probes = [p for p in counter
                 if re.match(r"^/(admin|admin/backend)/[a-z0-9]{8}\.[a-z0-9]{5}$", p)]
    print("  --od 目录的 dircheck 请求数: %d (应为 0)" % len(od_probes))
    assert not od_probes, od_probes

    # 报告里不应出现 [od] 占位项
    report = "\n".join(output.format_report(st, args))
    print("  --- 报告 ---")
    for line in report.splitlines():
        print("   |", line)
    assert "[od]" not in report, report
    print("  test_ok_dirs_skips_probe_and_recurses OK")


def test_scan_starts_from_root_with_od():
    """--od 不能让扫描从 /tc 开始：根目录的词表项要先被扫到。

    两个层面的保证：
    1. --od 目录不预先写进结果（否则报告里它们永远排第一）；
    2. 同一目录的 common 组先于 backup 组放行（备份一个目录上千条，
       排在词表前面会把词表推到很后面）。
    """
    import re
    counter = []
    existing = {
        "/index.html": (200, b"idx"),
        "/tc": (200, b"tc"),
        "/tc/member": (200, b"mem"),
    }
    srv, url = start_server(make_handler(existing, counter=counter))
    tmp = os.path.join(HERE, "_tmp")
    if not os.path.isdir(tmp):
        os.makedirs(tmp)
    d = os.path.join(tmp, "ord_d.txt")
    f = os.path.join(tmp, "ord_f.txt")
    with open(d, "w") as fh:
        fh.write("tc\n")
    with open(f, "w") as fh:
        fh.write("index.html\n")

    args = cli.Args(cli.build_parser().parse_args(
        ["-u", url, "-d", d, "-f", f, "-t", "4", "-r", "3", "--timeout", "5",
         "--od", "tc/member/"]))
    de, _ = cli.load_wordlist(d, "dir")
    fe, _ = cli.load_wordlist(f, "file")
    printer = Cap()
    st = GlobalState(args)
    eng = engine.build(args, st, printer, rules.IgnoreRules([]),
                       rules.BypassRules([]), rules.CaseFilter(1), de, fe, [])

    order = []
    orig_add = GlobalState.add_result

    def spy(self, rec):
        ok = orig_add(self, rec)
        if ok:
            order.append(rec["path"])
        return ok

    GlobalState.add_result = spy
    try:
        eng.start()
        # 只要根目录两项都扫到就可以收工，不必等 1184 个备份任务跑完
        deadline = time.time() + 60
        while time.time() < deadline:
            if "index.html" in order and "tc" in order:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("超时未扫到根目录项: %s" % order)
    finally:
        GlobalState.add_result = orig_add
        st.pause_event.set()
        with st.lock:
            st.cond.notify_all()
        for w in eng.workers:
            w.join(timeout=3.0)
        srv.shutdown()

    print("  结果顺序: %s" % order[:8])
    assert "index.html" in order, "根目录词表项没被扫到: %s" % order
    assert "tc" in order, "根目录的 tc 没被扫到: %s" % order
    # 根目录项必须排在 --od 目录之前（它们本来就都是第 1 层，看谁先入队）
    assert order.index("index.html") < len(order), order
    # --od 目录不该预先占据结果首位
    assert order[0] in ("index.html", "tc"), "结果首位不该是 --od 项: %s" % order[0]

    # --od 目录确实参与了递归
    assert "tc/member" in st.opened, sorted(st.opened)
    print("  --od 参与递归: %s" % sorted(st.opened))
    print("  test_scan_starts_from_root_with_od OK")


def test_common_released_before_backup():
    """同一目录放行时 common 组必须先于 backup 组。"""
    st = GlobalState(mk_args())
    st.register_probes("d", 1)
    st.put_group("d", "common", [mk_task("zzz_wordlist")])
    st.put_group("d", "backup", [mk_task("db.zip"), mk_task("web.rar")])
    released = st.note_verdict("d", "dead", value=False)
    names = [t.name for t in released]
    print("  放行顺序: %s" % names)
    assert names[0] == "zzz_wordlist", "common 必须排在最前: %s" % names
    assert names[1:] == ["db.zip", "web.rar"], names
    print("  test_common_released_before_backup OK")


def test_pause_discards_inflight_live_log():
    """暂停后在途请求返回的实时日志要被丢弃，不能污染提示行。"""
    import io as _io

    class FakeTTY(_io.StringIO):
        def isatty(self):
            return True

    buf = FakeTTY()
    pr = output.Printer(live=True, stream=buf)
    args = mk_args()
    st = GlobalState(args)
    ctl = control.Controller(args, st, pr)

    pr.live_line(0, "nope1", False, speed=10.0)     # 临时行
    ctl.on_sigint(None, None)                        # 暂停
    snapshot = buf.getvalue()

    # 暂停期间在途请求返回
    pr.live_line(1, "inflight", False, speed=58.4)
    after = buf.getvalue()
    print("  暂停后在途日志被丢弃: %s" % (after == snapshot))
    assert after == snapshot, "暂停期间的实时日志应被丢弃: %r" % after[len(snapshot):]

    # 暂停提示必须独立成行
    idx = snapshot.find("====")
    assert idx > 0 and snapshot[idx - 1] == "\n", repr(snapshot[idx - 3:idx])

    # go 之后恢复输出
    ctl.dispatch(control.parse_command("go"))
    pr.live_line(2, "resumed", True, speed=1.0)
    print("  go 后恢复输出: %s" % ("resumed" in buf.getvalue()))
    assert "resumed" in buf.getvalue(), "go 之后应恢复实时日志"
    print("  test_pause_discards_inflight_live_log OK")


def test_od_opens_when_root_probe_fails():
    """根目录探测网络失败时，--od 目录仍必须登记。

    settle_failed_probe 走的是失败分支，不经过 handle 里的 is_probe 分支，
    曾经因此漏掉 maybe_open_ok_dirs，导致 --od 子树整棵静默漏扫。
    """
    import re
    from http.server import BaseHTTPRequestHandler

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *a):
            pass

        def _handle(self):
            path = self.path.split("?")[0]
            # 随机探测名与备份探针一律断开连接 -> 触发 ConnectionError
            if (re.match(r"^/[a-z0-9]{8}\.[a-z0-9]{4,5}$", path)
                    or path.startswith("/__probe__")):
                self.close_connection = True
                try:
                    self.connection.close()
                except Exception:
                    pass
                return
            table = {"/tc": (200, b"tc"), "/tc/member": (200, b"m"),
                     "/tc/admin": (200, b"a")}
            code, body = table.get(path, (404, b""))
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = _handle
        do_HEAD = _handle

    srv, url = start_server(H)
    tmp = os.path.join(HERE, "_tmp")
    if not os.path.isdir(tmp):
        os.makedirs(tmp)
    d = os.path.join(tmp, "opf_d.txt")
    f = os.path.join(tmp, "opf_f.txt")
    with open(d, "w") as fh:
        fh.write("tc\nmember\nadmin\n")
    with open(f, "w") as fh:
        fh.write("x\n")

    args = cli.Args(cli.build_parser().parse_args(
        ["-u", url, "-d", d, "-f", f, "-t", "2", "-r", "3", "--timeout", "3",
         "--rt", "0", "--od", "tc/member/"]))
    de, _ = cli.load_wordlist(d, "dir")
    fe, _ = cli.load_wordlist(f, "file")
    printer = Cap()
    st = GlobalState(args)
    eng = engine.build(args, st, printer, rules.IgnoreRules([]),
                       rules.BypassRules([]), rules.CaseFilter(1), de, fe, [])
    try:
        eng.start()
        deadline = time.time() + 60
        while time.time() < deadline:
            with st.lock:
                if (st.pending <= 0 and st.active <= 0) or st.stop_flag:
                    break
            time.sleep(0.05)
    finally:
        st.pause_event.set()
        with st.lock:
            st.cond.notify_all()
        for w in eng.workers:
            w.join(timeout=3.0)
        srv.shutdown()

    print("  opened: %s" % sorted(st.opened))
    print("  结果: %s" % sorted(r["url"].replace(url, "")
                               for r in st.results))
    # --od 两层都必须登记
    assert "tc" in st.opened, "根目录探测失败时 --od 未登记: %s" % sorted(st.opened)
    assert "tc/member" in st.opened, sorted(st.opened)
    # 递归确实扫到了 tc/ 子树
    paths = [r["url"].replace(url, "") for r in st.results]
    assert "/tc" in paths, paths
    assert "/tc/admin" in paths, "tc/ 子树漏扫: %s" % paths
    print("  test_od_opens_when_root_probe_fails OK")


def main():
    output.setup_console()
    tests = [
        ("速度统计", test_speed_window),
        ("WAF 单项拉黑", test_waf_single_name_blocked),
        ("WAF 多项只移除自己", test_waf_shared_blame_removed),
        ("WAF 未到时长不结算", test_waf_not_due_early),
        ("WAF 拉黑后不再入队", test_waf_bypass_filters_tasks),
        ("WAF 阈值判定", test_waf_watch_needs_threshold),
        ("线程失败计数", test_thread_health_counters),
        ("其他线程都在暂停", test_all_other_threads_idle),
        ("其他线程都健康", test_all_other_threads_healthy),
        ("连续失败惩罚暂停", test_thread_penalty_pauses),
        ("WAF 等待自动恢复", test_waf_wait_auto_resume),
        ("WAF 等待按键进 REPL", test_waf_wait_keypress_goes_repl),
        ("WAF 等待停住请求", test_waf_wait_pauses_requests),
        ("Speed 只在实时日志", test_live_log_has_speed_not_in_report),
        ("IP 备份名无排列组合", test_ip_backup_names_no_permutations),
        ("实时日志路径对齐", test_live_path_alignment),
        ("Ctrl+C 另起新行", test_ctrl_c_starts_new_line),
        ("Ctrl+C 两次退出", test_ctrl_c_twice_stops),
        ("r 层级解析", test_depth_range_parse),
        ("r 层级语义", test_depth_allowed_semantics),
        ("remark 字段解析", test_remark_field_parsing),
        ("remark 仅非404显示", test_remark_shown_only_on_non_404),
        ("示例提示", test_error_shows_demos),
        ("--od 解析", test_ok_dirs_parsing),
        ("--od 跳过探测并递归", test_ok_dirs_skips_probe_and_recurses),
        ("从根目录开始扫", test_scan_starts_from_root_with_od),
        ("common 先于 backup", test_common_released_before_backup),
        ("暂停丢弃在途日志", test_pause_discards_inflight_live_log),
        ("根目录探测失败仍开 --od", test_od_opens_when_root_probe_fails),
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
