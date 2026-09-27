# -*- coding: utf-8 -*-
"""扫描控制：Ctrl+C 暂停、指令 REPL、线程数增减。

设计取舍
--------
扫描跑在主线程里而不是反过来，是因为信号处理函数只在主线程执行。要让
Ctrl+C 立刻响应，主线程必须站在 ``signal`` 能回调的位置上。所以：

* 主线程：装信号处理器、跑 ``run()`` 的等待循环、暂停时读指令
* 工作线程：daemon 线程，负责发请求

指令解析拆成纯函数 ``parse_command``，不依赖全局状态，便于单测。
"""

import re
import sys
import time

from . import models
from .output import safe_print

COMMANDS = ("rp", "at", "status", "exec", "go", "pause", "stop", "help", "?")

_HELP = """
可用指令:
  rp <path>      移除已存在的结果（前缀匹配，如 rp admin_x 清掉 admin_*）
  at <n>         增加 n 个线程；n 为负数表示减少
  status         显示当前扫描状态
  exec <code>    临时执行代码，如 exec test_list.add(123)
  go             继续扫描
  pause          保持暂停
  stop           终止扫描
  help           显示本帮助
""".strip()


def _human_wait(seconds):
    """把秒数说成人话：30 分钟 / 90 秒。"""
    if seconds >= 60:
        return "%.0f 分钟" % (seconds / 60.0)
    return "%.0f 秒" % seconds


class Command(object):
    """解析后的指令。"""

    __slots__ = ("name", "arg", "raw", "error")

    def __init__(self, name, arg=None, raw="", error=None):
        self.name = name
        self.arg = arg
        self.raw = raw
        self.error = error

    def __repr__(self):
        return "<Command %s %r>" % (self.name, self.arg)


def parse_command(line):
    """把一行输入解析成 Command。纯函数，方便测试。

    未知指令返回 name='unknown'，由调用方提示。
    """
    line = (line or "").strip()
    if not line:
        return Command("noop", raw=line)
    parts = line.split(None, 1)
    name = parts[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""

    if name in ("help", "?"):
        return Command("help", raw=line)
    if name == "status":
        return Command("status", raw=line)
    if name == "go":
        return Command("go", raw=line)
    if name == "pause":
        return Command("pause", raw=line)
    if name == "stop":
        return Command("stop", raw=line)
    if name == "rp":
        if not arg:
            return Command("rp", raw=line, error="rp 需要一个路径前缀")
        return Command("rp", arg=arg, raw=line)
    if name == "at":
        if not arg:
            return Command("at", raw=line, error="at 需要一个线程数")
        try:
            return Command("at", arg=int(arg), raw=line)
        except ValueError:
            return Command("at", raw=line, error="at 的参数必须是整数")
    if name == "exec":
        if not arg:
            return Command("exec", raw=line, error="exec 需要一段代码")
        return Command("exec", arg=arg, raw=line)
    return Command("unknown", arg=line, raw=line,
                   error="未知指令 %r，输入 help 查看帮助" % name)


class Controller(object):
    """暂停期间处理用户指令。"""

    def __init__(self, args, state, printer, engine=None):
        self.args = args
        self.state = state
        self.printer = printer
        self.engine = engine
        self.paused_by_user = False
        # exec 指令的命名空间：既能访问全局配置，也能操作任务列表。
        # test_list / task_list / globalTaskList 都指向同一个队列，
        # 规格里的示例用的是 test_list.add(123)。
        self.namespace = {
            "globalConfig": args,
            "args": args,
            "globalTaskList": state.queue,
            "task_list": state.queue,
            "test_list": state.queue,
            "state": state,
            "printer": printer,
            "engine": engine,
        }

    # ------------------------------------------------------------------
    def on_sigint(self, signum, frame):
        """Ctrl+C：第一次暂停，暂停中再按直接退出。"""
        state = self.state
        # 先把实时日志的临时行收尾成独立一行，否则提示会接在日志后面。
        # suspend_live 已经换过行了，这里不再多打一个空行。
        self.printer.suspend_live()
        if not state.pause_event.is_set():
            # 已经在暂停中，用户又按了一次 —— 直接走
            self.printer.raw("* 再次中断，直接退出")
            state.stop_flag = True
            with state.lock:
                state.cond.notify_all()
            return
        state.pause_requested = True
        state.pause_event.clear()
        self.printer.raw("=" * 66)
        self.printer.raw("* 已暂停。输入指令继续（help 查看可用指令）")
        self.printer.raw("=" * 66)

    # ------------------------------------------------------------------
    def enter_waf_wait(self):
        """进入 WAF 拦截等待模式。

        表现与 Ctrl+C 暂停相同（暂停扫描、可以敲指令），但额外做两件事：
        * 检测按键：有按键就停在 REPL 里等人处理；
        * 长时间没有任何按键 -> 视为无人值守，自动 go 恢复扫描。
        """
        state = self.state
        if state.waf_waiting:
            return
        idle = models.WAF_IDLE_RESUME
        state.waf_waiting = True
        state.pause_event.clear()
        state.pause_requested = False
        self.printer.suspend_live()
        self.printer.raw("=" * 66)
        self.printer.raw("* WAF 拦截等待模式：疑似被拦截，已暂停扫描")
        self.printer.raw("* %s 内无按键将自动恢复；输入指令可手动处理"
                         % _human_wait(idle))
        self.printer.raw("=" * 66)
        try:
            got_key = self._wait_for_key(idle)
        finally:
            state.waf_waiting = False

        if state.stop_flag:
            return
        if got_key:
            # 有人操作：交给 REPL，由用户决定 go / stop
            self.printer.raw("* 检测到输入，进入指令模式")
            self.repl()
            return
        # 无人值守：自动恢复
        self.printer.info("无人值守 %s，自动恢复扫描" % _human_wait(idle), tag="*")
        state.pause_requested = False
        state.pause_event.set()
        with state.lock:
            state.cond.notify_all()

    def _wait_for_key(self, seconds):
        """等待按键，最多 seconds 秒。返回 True 表示有按键。

        优先用 msvcrt（Windows，非阻塞且不需要回车）；没有就退回 select
        （POSIX）。两者都不可用时退化成单纯等待，仍能触发自动恢复。
        """
        end = time.time() + seconds
        reader = self._make_key_reader()
        while time.time() < end:
            if self.state.stop_flag:
                return False
            if reader is not None and reader():
                return True
            time.sleep(0.2)
        return False

    def _make_key_reader(self):
        """返回一个「是否有按键」的探测函数，做不到就返回 None。"""
        try:
            import msvcrt

            def _read_win():
                try:
                    if msvcrt.kbhit():
                        msvcrt.getch()      # 吃掉这个键，避免污染后续输入
                        return True
                except Exception:
                    pass
                return False
            return _read_win
        except ImportError:
            pass
        try:
            import select

            def _read_posix():
                try:
                    ready, _, _ = select.select([sys.stdin], [], [], 0)
                    return bool(ready)
                except Exception:
                    return False
            return _read_posix
        except ImportError:
            return None

    # ------------------------------------------------------------------
    def repl(self):
        """暂停期间读指令。返回 True 表示继续扫描，False 表示终止。"""
        while True:
            try:
                line = self._readline()
            except (EOFError, KeyboardInterrupt):
                self.printer.raw("")
                self.printer.raw("* 输入结束，终止扫描")
                return False
            cmd = parse_command(line)
            if cmd.error:
                self.printer.raw("! %s" % cmd.error)
                continue
            go = self.dispatch(cmd)
            if go is not None:
                return go
        return True

    def _readline(self):
        sys.stdout.write("pathscan> ")
        try:
            sys.stdout.flush()
        except Exception:
            pass
        return sys.stdin.readline()

    # ------------------------------------------------------------------
    def dispatch(self, cmd):
        """执行指令。返回 True=继续, False=终止, None=仍处于暂停。"""
        state = self.state
        name = cmd.name
        if name == "noop":
            return None
        if name == "help":
            self.printer.raw(_HELP)
            return None
        if name == "status":
            self.print_status()
            return None
        if name == "go":
            state.pause_requested = False
            state.pause_event.set()
            with state.lock:
                state.cond.notify_all()
            self.printer.raw("* 继续扫描")
            return True
        if name == "pause":
            self.printer.raw("* 保持暂停")
            return None
        if name == "stop":
            state.stop_flag = True
            state.pause_event.set()
            with state.lock:
                state.cond.notify_all()
            self.printer.raw("* 终止扫描")
            return False
        if name == "rp":
            n = state.suppress(cmd.arg)
            self.printer.raw("* 已移除 %d 条匹配 %r 的结果" % (n, cmd.arg))
            return None
        if name == "at":
            self.adjust_threads(cmd.arg)
            return None
        if name == "exec":
            self.run_code(cmd.arg)
            return None
        self.printer.raw("! 未知指令，输入 help 查看帮助")
        return None

    # ------------------------------------------------------------------
    def adjust_threads(self, delta):
        args = self.args
        state = self.state
        if delta > 0:
            if self.engine is None:
                self.printer.raw("! 引擎未就绪，无法调整线程")
                return
            from .engine import Worker
            with state.lock:
                state.target_threads += delta
                base = len(self.engine.workers)
            for i in range(delta):
                w = Worker(self.engine, base + i)
                self.engine.workers.append(w)
                w.start()
            self.printer.raw("* 线程数 +%d，当前目标 %d"
                             % (delta, state.target_threads))
        elif delta < 0:
            n = -delta
            retired = 0
            # 优先让正在跑的线程自己退出
            workers = self.engine.workers if self.engine else []
            for w in workers:
                if retired >= n:
                    break
                if not getattr(w, "retire", False):
                    w.retire = True
                    retired += 1
            with state.lock:
                state.target_threads = max(1, state.target_threads - n)
                state.cond.notify_all()
            self.printer.raw("* 已通知 %d 个线程退出，当前目标 %d"
                             % (retired, state.target_threads))
        else:
            self.printer.raw("* 线程数未变化")

    def run_code(self, code):
        """执行 exec 指令的代码片段。"""
        try:
            exec(compile(code, "<exec>", "exec"), self.namespace)
        except Exception as exc:
            self.printer.raw("! exec 失败: %s: %s" % (type(exc).__name__, exc))
            return
        self.printer.raw("* 执行完成")

    # ------------------------------------------------------------------
    def print_status(self):
        snap = self.state.snapshot()
        elapsed = max(snap["elapsed"], 1e-6)
        rate = snap["done"] / elapsed
        speed = self.state.speed()
        fails = self.state.thread_fails
        busy = [t for t, n in fails.items() if n]
        self.printer.raw("-" * 66)
        self.printer.raw(" 状态: %s" % ("已暂停" if not self.state.pause_event.is_set()
                                        else "运行中"))
        self.printer.raw(" 已完成 %d  队列 %d  进行中 %d"
                         % (snap["done"], snap["queued"], snap["active"]))
        self.printer.raw(" 结果 %d  忽略 %d  失败 %d  死目录 %d"
                         % (snap["results"], snap["ignored"], snap["errors"],
                            snap["dead_dirs"]))
        self.printer.raw(" 线程 %d/%d  耗时 %.1fs  均速 %.1f req/s  实时 %.1f req/s"
                         % (snap["threads_alive"], snap["target_threads"],
                            snap["elapsed"], rate, speed))
        if busy:
            self.printer.raw(" 连续失败中的线程: %s"
                             % ", ".join("#%d=%d" % (t, n)
                                         for t, n in sorted(busy.items())))
        if self.state.waf_ignored:
            self.printer.raw(" WAF 忽略的名称: %s"
                             % ", ".join(self.state.waf_ignored))
        self.printer.raw("-" * 66)


def install(args, state, printer, controller):
    """把 SIGINT 接到 controller 上。"""
    import signal
    def handler(signum, frame):
        controller.on_sigint(signum, frame)
    try:
        signal.signal(signal.SIGINT, handler)
    except ValueError:
        # 不在主线程时无法安装，交由调用方处理
        pass


def pause_loop(controller, engine):
    """主线程等待循环：只在暂停时进 REPL，否则只做保活检查。

    同时负责两件周期性工作：
    * 统计 WAF 观察窗口（5 秒到点就判定）；
    * 响应工作线程发起的 WAF 等待模式请求。
    """
    state = controller.state
    last_sweep = 0.0
    while True:
        with state.lock:
            done = state.pending <= 0 and state.active <= 0
            stopped = state.stop_flag
            notified = state.pause_requested
        if stopped:
            return False
        if done:
            return True

        # WAF 观察窗口统计（每 0.5 秒扫一次，够及时也不费 CPU）
        now = time.time()
        if now - last_sweep >= 0.5:
            last_sweep = now
            if engine is not None:
                try:
                    engine.waf_sweep()
                except Exception:
                    pass

        # 工作线程请求进入 WAF 等待模式
        if state.take_wait_request():
            controller.enter_waf_wait()
            continue

        if notified:
            state.pause_requested = False
            if not controller.repl():
                return False
        time.sleep(0.15)
