# -*- coding: utf-8 -*-
"""输出层：实时日志、结果渲染、最终报告、--of 导出。

cp936 控制台的坑
----------------
实测目标环境 ``sys.stdout.encoding`` 是 cp936。路径里带个 'ü' 之类的字符就会
抛 UnicodeEncodeError 把整个扫描带崩。这里做了三层防护：
1. 启动时把 stdout 重配成 utf-8/replace（Python 3.7 支持 reconfigure）；
2. 渲染每行时对不可编码字符做替换；
3. print 本身兜底 try/except，任何情况下都不让打印异常杀死扫描线程。

实时日志
--------
每次请求完成后打一条 ``ThreadID:x  ->  /path [ok|err]``。

* ``[err]``（404 / 被规则判为 404 / 网络失败）只是「路过」，用 ``\\r`` 覆盖，
  会被后续请求刷掉；
* ``[ok]``（命中）会固定下来，之后的日志另起新行。

非 TTY（重定向到文件、管道）或 ``--cq`` 时自动关闭覆盖行为，避免把 ``\\r``
写进日志文件。
"""

import io
import sys
import threading
import time

# 复刻 reconfigure 的用途，但兼容更老的 Python
_ORIG_STDOUT = sys.stdout

# 实时日志里路径的对齐宽度；超过则原样输出（允许不对齐）
LIVE_PATH_WIDTH = 40


def setup_console():
    """让控制台能安全输出任意 Unicode。"""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None:
            continue
        reconf = getattr(stream, "reconfigure", None)
        if reconf is not None:
            try:
                reconf(encoding="utf-8", errors="replace")
                continue
            except Exception:
                pass
        # 老环境退路：包一层 utf-8 写出
        try:
            buf = getattr(stream, "buffer", None)
            if buf is not None:
                setattr(sys, name, io.TextIOWrapper(
                    buf, encoding="utf-8", errors="replace", line_buffering=True))
        except Exception:
            pass


def safe_print(line, stream=None):
    """绝不抛异常的输出。"""
    stream = stream or sys.stdout
    try:
        stream.write(line + "\n")
        stream.flush()
    except UnicodeEncodeError:
        try:
            enc = getattr(stream, "encoding", None) or "ascii"
            stream.write(line.encode(enc, "replace").decode(enc) + "\n")
            stream.flush()
        except Exception:
            pass
    except Exception:
        pass


def human_size(n):
    """把字节数变成短标签，输出时对齐用。"""
    if n is None:
        return "-"
    if n < 1000:
        return str(n)
    for unit in ("K", "M", "G"):
        n //= 1000
        if n < 1000:
            return "%d%s" % (n, unit)
    return "%dT" % n


def status_marker(name):
    """实时日志里的标记：ok=命中会保留，err=会被刷掉。

    ``[ok ]`` 补一个空格，长度与 ``[err]`` 对齐。
    """
    return "ok " if name else "err"


class Printer(object):
    """带锁的打印器。多线程共用，保证一行不会被另一行切碎。

    实时日志的临时行由同一个锁保护：任何要换行的输出都会先把临时行清掉，
    否则信息会黏在临时行后面。
    """

    def __init__(self, quiet=False, live=True, stream=None):
        self.lock = threading.RLock()
        self.quiet = quiet
        self.stream = stream or sys.stdout
        self.live_enabled = bool(live) and not quiet and self._is_tty()
        self._pending_len = 0        # 当前未换行的临时行长度
        self._live_paused = False    # 暂停期间不再输出实时日志

    def _is_tty(self):
        try:
            return bool(self.stream.isatty())
        except Exception:
            return False

    # ------------------------------------------------------------------
    # 基础输出
    # ------------------------------------------------------------------
    def _clear_pending_locked(self):
        """清掉未换行的临时行，让接下来的输出从行首开始。

        先把光标回行首再整行擦掉，避免残留字符混进下一行输出。
        """
        if not self._pending_len:
            return
        try:
            self.stream.write("\r" + " " * self._pending_len + "\r")
            self.stream.flush()
        except Exception:
            pass
        self._pending_len = 0

    def raw(self, line="", stream=None):
        with self.lock:
            if stream is None:
                self._clear_pending_locked()
            safe_print(line, stream or self.stream)

    def info(self, msg, tag="*"):
        if not self.quiet:
            self.raw("%s %s" % (tag, msg))

    def result(self, rec):
        """渲染一条命中结果（固定行）。"""
        self.raw(format_line(rec))

    # ------------------------------------------------------------------
    # 实时日志
    # ------------------------------------------------------------------
    def live_line(self, thread_id, path, ok, speed=None, remark=""):
        """打一条实时日志。ok=True 时固定，否则会被后续请求覆盖。

        实时日志只走屏幕，从不写进 --of 的文件（导出走 format_report）。
        路径不足 LIVE_PATH_WIDTH 时补空格对齐；超长则原样输出（此时会牺牲
        对齐，但信息完整优先）。

        备注只在 ok（请求非 404，含未被规则视为 404）时显示——
        与备注的值本身无关，所以这里的门控不放给调用方。

        暂停期间（suspend_live 之后）直接丢弃：在途请求返回时扫描已经停了，
        再打日志会接在暂停提示或指令提示符后面。
        """
        # 先按「纯前缀 + 路径」拼，路径对齐到固定宽度
        head = "ThreadID:%d  ->  " % thread_id
        body = ("/" + path).ljust(LIVE_PATH_WIDTH)
        text = "%s%s [%s]" % (head, body, status_marker(ok))
        if speed is not None:
            text += "  Speed: %.1f/s" % speed
        if ok and remark:
            text += "  #%s" % remark
        with self.lock:
            if self._live_paused:
                return
            if not self.live_enabled:
                # 非 TTY：只保留命中行，免得 404 把文件刷爆
                if ok:
                    safe_print(text, self.stream)
                return
            if ok:
                # 命中：先清掉临时行，再固定输出，之后的日志另起一行
                self._clear_pending_locked()
                safe_print(text, self.stream)
            else:
                self._transient_locked(text)

    def _transient_locked(self, text):
        """用 \\r 覆盖上一条临时行。"""
        pad = max(0, self._pending_len - len(text))
        try:
            # 行首先回 \r 并清空上一行，确保不会接在已有内容后面
            self.stream.write("\r" + text + " " * pad)
            self.stream.flush()
            self._pending_len = len(text)
        except Exception:
            # 写失败就退回普通输出，不能让日志把扫描搞崩
            self._pending_len = 0
            safe_print(text, self.stream)

    def suspend_live(self):
        """暂停/中断前调用：把临时行收尾成独立的一行，并停止接收实时日志。

        不这么做的话，Ctrl+C 的提示会接在实时日志那一行后面；而且在途请求
        返回后还会继续打日志，接在提示或指令提示符后面。
        """
        with self.lock:
            self._live_paused = True
            if not self._pending_len:
                return
            try:
                self.stream.write("\n")
                self.stream.flush()
            except Exception:
                pass
            self._pending_len = 0

    def clear_pending(self):
        """清掉未换行的临时行（提示符前调用）。"""
        with self.lock:
            self._clear_pending_locked()

    def resume_live(self):
        """恢复实时日志（继续扫描时调用）。"""
        with self.lock:
            self._live_paused = False

    def finish_live(self):
        """扫描结束：把残留的临时行清掉。"""
        with self.lock:
            self._clear_pending_locked()


def _code_bits(rec):
    """``[200] (1234)`` 或 ``[302] (0) -> /xx1``。

    ``code`` 为 None 时：``from == "okdir"`` 是 --od 预置的目录，标 ``[od]``；
    其余（重试超限）标 ``[ERR]``。
    """
    code = rec.get("code")
    if code is None:
        head = "[od]" if rec.get("from") == "okdir" else "[ERR]"
    else:
        head = "[%d]" % code
    size = human_size(rec.get("size"))
    out = "%s (%s)" % (head, size)
    loc = rec.get("location")
    if loc:
        out += " -> %s" % loc
    return out


def format_line(rec):
    """导出到文件时用的纯文本行。"""
    line = "%s %s" % (_code_bits(rec), rec.get("url", ""))
    if rec.get("remark"):
        line += "  #%s" % rec["remark"]
    if rec.get("from"):
        line += "  {%s}" % rec["from"]
    return line


def _dirs_only(entries):
    """只留目录类条目：报告的可读性靠它，见 format_report 的说明。"""
    return [e for e in entries if e.get("type") == "dir"]


def _section(lines, title, entries, show_remark=False):
    """渲染报告里的一个小节。

    show_remark 只在「非 404」的小节（Result(OK)）为 True——
    备注的显示取决于请求结果是否为 404，与备注的值无关。
    """
    lines.append("%s:" % title)
    if not entries:
        lines.append("    (none)")
        return
    paths = ["/" + (e.get("path") or "") for e in entries]
    width = max(len(p) for p in paths)
    for path, entry in zip(paths, entries):
        line = "    %s  %s" % (path.ljust(width), _code_bits(entry))
        if show_remark and entry.get("remark"):
            line += "  #%s" % entry["remark"]
        lines.append(line)


def format_report(state, args):
    """扫描完成后的汇总报告。

    ::

        http://target/
        Ignored Paths:
             /xx   [302] (0) -> /xx1
             /xx1  [200] (99)
        Result(OK):
            /xx2  [200] (1234)

    两个小节都只列**目录**：目录代表「这里没继续往下扫」或「这里存在」，
    是报告真正要传达的信息；文件和备份路径数量大且多为 404 噪声，
    逐条列出会把报告刷爆，所以它们只在实时日志里留一行。

    Ignored Paths 里的条目本身就是被判为 404 的，所以不显示备注；
    备注只出现在 Result(OK) 里。
    """
    lines = []
    lines.append(args.url + "/")
    _section(lines, "Ignored Paths", _dirs_only(state.ignored))
    _section(lines, "Result(OK)", _dirs_only(state.results), show_remark=True)
    if state.errors:
        lines.append("")
        _section(lines, "Errors", _dirs_only(state.errors), show_remark=True)
    return lines


def print_report(state, args, printer):
    for line in format_report(state, args):
        printer.raw(line)


def write_output(path, state, args):
    """把结果与失败项写到 --of 指定文件。"""
    lines = []
    lines.append("# PathScan 扫描结果")
    lines.append("# 目标: %s" % args.url)
    lines.append("# 时间: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("# 结果数: %d  忽略数: %d  失败数: %d"
                 % (len(state.results), len(state.ignored),
                    len(state.errors)))
    lines.append("")
    for line in format_report(state, args):
        lines.append(line)

    try:
        with io.open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write("\n".join(lines) + "\n")
        return True, None
    except Exception as exc:
        return False, str(exc)
