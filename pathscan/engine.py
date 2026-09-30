# -*- coding: utf-8 -*-
"""调度引擎：任务队列 + 线程池 + 递归展开。

线程模型
--------
主线程负责信号处理与指令 REPL，工作线程跑扫描。工作线程全部是 daemon，
这样连按两次 Ctrl+C 一定能退出，不会被卡住的 socket 拖住。

结束条件
--------
``pending`` 归零才算扫完。pending 包含「在队列里 + 正在请求」的任务数，
所以目录探测任务还在飞的时候不会被误判成已经穷尽。
"""

import threading
import time

from . import probes
from .models import (THREAD_FAIL_LIMIT, THREAD_FAIL_PAUSE,
                     WAF_FAIL_THRESHOLD, Task, path_depth)
from .output import safe_print
from .scanner import Scanner, build_url


class Worker(threading.Thread):
    """一个工作线程，持有自己的 requests.Session。"""

    def __init__(self, engine, thread_id):
        threading.Thread.__init__(self)
        self.daemon = True
        self.engine = engine
        self.thread_id = thread_id
        self.name = "worker-%d" % thread_id
        self.scanner = Scanner(engine.args, thread_id)
        self.retire = False

    # ------------------------------------------------------------------
    def run(self):
        state = self.engine.state
        with state.lock:
            state.threads_alive += 1
        state.thread_register(self.thread_id)
        try:
            while True:
                state.pause_event.wait()
                if state.stop_flag or self.retire or self.engine.should_retire(self):
                    break
                task = state.take()
                if task is None:
                    # take 返回 None 表示「暂时没活」。不能就此退出——用户在
                    # 暂停时敲的 ed / od 会在扫描空转后追加新任务，线程必须
                    # 还在，否则新任务没人消费。真正结束由主线程置 stop_flag。
                    if state.stop_flag or self.retire:
                        break
                    state.wait_for_work()
                    continue
                try:
                    self.handle(task)
                except Exception as exc:                # 任何任务级异常都不能杀线程
                    self.engine.printer.raw("! 任务处理异常 %s: %r"
                                            % (task.path, exc))
                finally:
                    state.complete(task)
        finally:
            with state.lock:
                state.threads_alive -= 1
                state.cond.notify_all()
            state.thread_unregister(self.thread_id)
            self.scanner.close()

    # ------------------------------------------------------------------
    def handle(self, task):
        engine = self.engine
        state = engine.state
        args = engine.args

        if engine.hit_suppressed(task.path):
            return
        if state.is_name_blocked(task.name):
            return

        url = build_url(args.url, task.path, task.type, args.mode)

        # 目录本身或其上级已被判 404，直接跳过
        if task.type == "dir" and task.parent and state.is_dead_dir(task.parent):
            return
        # 该目录下这个后缀被判定为不可用
        if task.type == "file" and args.suffixes:
            suf = "." + task.suffix
            if not state.ext_usable(task.parent, suf):
                return

        scanner = self.scanner
        scanner.sleep_interval()
        resp = scanner.fetch(url)
        state.record_request()

        # ---- 网络层失败：重试 ----
        if resp.error is not None:
            self.live(task, url, False)
            self.note_request_result(False)
            engine.waf_watch(task)          # 失败累计到阈值则纳入观察
            task.trytimes += 1
            if task.waf:
                state.waf_hit(task.name, task.waf)
            if task.trytimes > args.rt:
                state.add_error(task, url, resp.error)
                self.engine.report_error(task, url, resp.error)
                # 探测任务失败也必须结算，否则该目录的延迟组永远等不到放行
                self.engine.settle_failed_probe(task)
            else:
                state.enqueue([task])
            return

        # 走到这里说明网络层是通的
        self.note_request_result(True)

        # 探测任务不参与实时日志与结果记录（它们本来就是随机路径）
        if self.is_probe(task):
            rule = engine.ignore_rules.matched(resp._resp, resp.code,
                                               resp.size)
            if task.from_ == "dircheck":
                engine.on_dircheck_result(task, url, resp)
            elif task.from_ == "suffixcheck":
                engine.on_suffix_result(task, url, resp)
            else:
                engine.on_backup_probe_result(task, url, resp)
            # 根目录探测结算完就可以登记 --od 目录了
            engine.maybe_open_ok_dirs()
            return

        # ---- 忽略规则：判定为 404，记入 Ignored Paths，不递归 ----
        rule = engine.ignore_rules.matched(resp._resp, resp.code, resp.size)
        if rule is not None:
            reason = "--ir %s %s" % (rule["attr"], rule["raw"])
            self.live(task, url, False)
            state.add_ignored(task, url, resp.code, resp.size,
                              resp.location, reason)
            engine.debug("忽略 %s (%s)" % (url, reason))
            return

        exists = resp.exists
        if not exists:
            self.live(task, url, False)
            return

        # ---- 命中 ----
        remark = engine.remark_for(task)
        rec = {
            "path": task.path,
            "url": url,
            "type": task.type,
            "code": resp.code,
            "size": resp.size,
            "location": resp.location,
            "from": task.from_,
            "remark": remark,
            "depth": task.depth,
        }
        if not state.add_result(rec):
            # 去重命中（同一个 url+type 已经记录过），不重复打日志
            return
        self.live(task, url, True)
        if task.waf:
            state.waf_hit(task.name, task.waf)

        # ---- 递归 ----
        if task.type == "dir":
            engine.expand_dir(task, url)

    @staticmethod
    def is_probe(task):
        """是否是探测任务（dircheck / 后缀检测 / 备份探针）。"""
        if task.from_ in ("dircheck", "suffixcheck"):
            return True
        return task.from_ == "backup" and task.name.startswith("__probe__")

    def live(self, task, url, ok):
        """打一条实时日志（带速度与备注）。只输出到屏幕，不写 --of。

        remark 的显示门控在 Printer.live_line 里（只在 ok 时显示），
        这里照常把备注传进去即可。
        """
        self.engine.printer.live_line(self.thread_id, task.path, ok,
                                      self.engine.state.speed(),
                                      self.engine.remark_for(task))

    # ------------------------------------------------------------------
    # 线程健康度：连续失败则惩罚性暂停，必要时转 WAF 等待模式
    # ------------------------------------------------------------------
    def note_request_result(self, ok):
        """记录本次请求结果，维护连续失败计数与惩罚暂停。

        成功 -> 计数清零；
        失败 -> 计数 +1，达到上限暂停 THREAD_FAIL_PAUSE 秒。
        暂停结束后：若其他线程也都在暂停，说明是 IP 级封禁，转 WAF 等待模式；
        若其他线程都健康，自己继续跑。
        """
        state = self.engine.state
        if ok:
            state.thread_success(self.thread_id)
            return
        n = state.thread_fail(self.thread_id)
        if n < THREAD_FAIL_LIMIT:
            return

        state.thread_pause(self.thread_id)
        try:
            self.engine.printer.info(
                "线程 %d 连续失败 %d 次，暂停 %.0fs"
                % (self.thread_id, n, THREAD_FAIL_PAUSE), tag="!")
            if self._sleep_interruptible(THREAD_FAIL_PAUSE):
                return                      # 被终止/惩罚期间收到指令

            if state.all_other_threads_idle(self.thread_id):
                # 所有线程都在暂停 -> IP 大概率被封，转 WAF 等待模式
                self.engine.printer.info(
                    "所有线程均失败暂停，疑似 IP 被拦截，进入 WAF 等待模式",
                    tag="!")
                state.waf_request_wait()
            else:
                self.engine.printer.info(
                    "线程 %d 恢复（其他线程正常）" % self.thread_id, tag="*")
        finally:
            state.thread_resume(self.thread_id)

    def _sleep_interruptible(self, seconds):
        """可被终止打断的睡眠。返回 True 表示应尽快收手。"""
        state = self.engine.state
        end = time.time() + seconds
        while time.time() < end:
            if state.stop_flag:
                return True
            time.sleep(0.2)
        return False


class Engine(object):
    """扫描调度器。"""

    def __init__(self, args, state, printer, ignore_rules, bypass_rules,
                 case_filter):
        self.args = args
        self.state = state
        self.printer = printer
        self.ignore_rules = ignore_rules
        self.bypass_rules = bypass_rules
        self.case_filter = case_filter
        self.workers = []
        self.dir_entries = []
        self.file_entries = []
        self.files_ext_entries = []
        self.debug_on = False
        self._dir_entry_by_name = {}
        # --od 的延迟登记状态（见 start / maybe_open_ok_dirs）
        self._ok_dirs_pending = []
        self._ok_dirs_done = True

    # ------------------------------------------------------------------
    def debug(self, msg):
        if self.debug_on:
            self.printer.raw("  · %s" % msg)

    def should_retire(self, worker):
        return worker.retire

    def hit_suppressed(self, path):
        return self.state.is_suppressed(path)

    def remark_for(self, task):
        """备注按「任务自身 > 父目录词表条目」的顺序取。"""
        if task.remark:
            return task.remark
        entry = self._dir_entry_by_name.get(task.parent)
        if entry:
            return entry.get("remark", "")
        return ""

    def report_error(self, task, url, reason):
        self.printer.raw("[ERR]  tries=%d  %s  (%s)"
                         % (task.trytimes, url, reason))

    # ------------------------------------------------------------------
    # WAF 自动检测
    # ------------------------------------------------------------------
    def waf_watch(self, task):
        """路径失败次数累计到阈值时，把 name 纳入 5 秒观察窗口。

        这里用的是 task.trytimes（该路径自身的失败次数），达到
        WAF_FAIL_THRESHOLD 就开始观察。窗口结束时由 waf_sweep 判定。
        """
        if task.trytimes < WAF_FAIL_THRESHOLD:
            return
        if self.state.is_name_bypassed(task.name):
            return
        if self.state.waf_note_fail(task.name):
            self.debug("WAF 观察: %s（失败 %d 次）" % (task.name, task.trytimes))

    def waf_sweep(self):
        """周期性统计观察窗口，把孤立的失败名称加入忽略列表。

        窗口到点后：只有它自己 -> 判定该名称触发 WAF，加入忽略列表；
        还有别的名称 -> 只移除当前项（说明是站点普遍问题，不是这个名称）。
        """
        blocked, dropped = self.state.waf_collect_due()
        for name in blocked:
            self.printer.info("WAF 检测: 名称 %r 加入忽略列表，后续不再检测"
                              % name, tag="!")
        for name in dropped:
            self.debug("WAF 观察: %s 移除（同期还有其他失败项）" % name)
        return blocked

    # ------------------------------------------------------------------
    # 入队辅助
    # ------------------------------------------------------------------
    def filter_tasks(self, tasks):
        """过滤任务：应用 --br 排除、rp 抑制与 WAF 拉黑。

        延迟组里的任务在「构建时」就要过一遍这里，不能等到放行时才过滤——
        放行走的 _select_releasable 只看探测结论，拿不到 --br 这些规则。

        注意这里**不做** claim_url 去重：去重是「这个 URL 已被调度」的登记，
        而延迟组是「将来可能调度」的暂存区。提前登记会让 --od 目录在构建
        父目录的常规任务时就把自己的 URL 占掉，等真正放行时反被去重丢弃，
        结果 --od 目录自己永远扫不到。
        """
        args = self.args
        state = self.state
        accepted = []
        for task in tasks:
            path = task.path
            url = build_url(args.url, path, task.type, args.mode)
            # 备注里的 "r" 限定层级，不在区间内的直接丢弃
            if not task.depth_allowed():
                continue
            if self.bypass_rules.blocked(task.name, path, url):
                continue
            if state.is_suppressed(path):
                continue
            if state.is_name_blocked(task.name):
                continue
            # WAF 自动检测加入忽略列表的名称，后续不再检测
            if state.is_name_bypassed(task.name):
                continue
            accepted.append(task)
        return accepted

    def add_tasks(self, tasks, source=""):
        """过滤 + 去重后入队。

        claim_url 放在真正入队的这一刻，保证「暂存」不消费去重名额。
        """
        accepted = []
        for task in self.filter_tasks(tasks):
            if not self.state.claim_url(task.path, task.type,
                                        bool(self.args.cs)):
                self.debug("去重跳过 %s" % task.path)
                continue
            accepted.append(task)
        if accepted:
            self.state.enqueue(accepted)
        return len(accepted)

    def build_common_tasks(self, parent):
        """为一个目录生成「常规」子任务：目录表 + 文件表 + 带后缀文件表。

        条目备注里的 "r" 字段会限定它只出现在指定层级，这里透传到 Task，
        由 filter_tasks 统一按当前深度过滤。
        """
        args = self.args
        tasks = []

        for entry in self.dir_entries:
            tasks.append(Task(type="dir", name=entry["name"], parent=parent,
                              from_="common", remark=entry["remark"],
                              waf=entry["waf"],
                              depth_lo=entry.get("depth_lo", 0),
                              depth_hi=entry.get("depth_hi")))
        for entry in self.file_entries:
            tasks.extend(probes.build_leaf_tasks(
                entry["name"], entry["remark"], entry["waf"], parent,
                "common", args, "file",
                entry.get("depth_lo", 0), entry.get("depth_hi")))
        for entry in self.files_ext_entries:
            tasks.append(Task(type="file", name=entry["name"], parent=parent,
                              from_="common", remark=entry["remark"],
                              waf=entry["waf"],
                              depth_lo=entry.get("depth_lo", 0),
                              depth_hi=entry.get("depth_hi")))
        # --ed / --ef 的额外项，根目录才加
        if parent == "":
            for name in args.ed_list:
                tasks.append(Task(type="dir", name=name, parent=parent,
                                  from_="common"))
            for name in args.ef_list:
                tasks.append(Task(type="file", name=name, parent=parent,
                                  from_="common"))
        return tasks

    # ------------------------------------------------------------------
    # 启动
    # ------------------------------------------------------------------
    def start(self):
        args = self.args
        state = self.state

        # 根目录：dircheck + 后缀探测 + 备份探针 + 备份任务
        self.open_dir("", is_root=True)

        # --od 指定的目录要等根目录结算后再打开，否则它们会插到根目录任务的
        # 前面——根目录任务在等探测，--od 任务却立即放行，扫描就从
        # /tc 而不是 / 开始了。
        self._ok_dirs_pending = list(args.ok_dirs)
        self._ok_dirs_done = not self._ok_dirs_pending
        self.maybe_open_ok_dirs()

        with state.lock:
            self.printer.info("队列已就绪，启动 %d 个线程..." % args.thread)
        for i in range(args.thread):
            w = Worker(self, i)
            self.workers.append(w)
            w.start()

    def maybe_open_ok_dirs(self):
        """根目录结算完成后，再登记 --od 目录。

        根目录的探测结论是「能不能扫」的前提（软 404 会直接终止），
        而且先放行根目录任务才能保证扫描从 / 开始。
        """
        if self._ok_dirs_done:
            return
        with self.state.lock:
            waiting = dict(self.state.probe_wait)
            # 根目录还有探测在飞，继续等
            if self.state.probe_wait.get(""):
                return
            self._ok_dirs_done = True
        self.debug("根目录探测结算完成（probe_wait=%s），开始登记 --od 目录"
                   % (waiting or "空"))
        self.open_ok_dirs()

    def open_ok_dirs(self):
        """登记 --od 指定的目录。

        由浅到深逐层处理：--od dir1/dir2/dir3/ 会依次处理 dir1、
        dir1/dir2、dir1/dir2/dir3。每一层做两件事：

        1. **请求它自身** —— 这是关键。--od 只是「打开它以便向下递归」，
           并不会请求这个目录；如果词表里没有同名的条目（或大小写对不上，
           比如词表是 ``Member`` 而路径是 ``member``），这个真实存在的
           目录就永远扫不到。
        2. **打开它以便递归** —— 跳过探测，直接按「存在 + 后缀全可用」结算。

        自身请求走正常入队（含 claim_url 去重），所以若词表之后又给出
        同一个路径，只会有一个请求发出。

        注意 --od 的路径是用户明确声明的「存在」，它的去重优先级高于词表：
        --cs 0 时若词表给的是不同大小写（用户写 tc/member，词表里是 Member），
        两者会归一化成同一个 key；此时必须保住 --od 的那个，否则真实存在的
        tc/member 会被 404 的 tc/Member 顶掉。做法是先占去重名额。
        """
        for path in self.args.ok_dirs:
            self.add_ok_dir(path)

    def queue_dir(self, parent, name):
        """把一个目录加入队列（ed 指令用）。返回入队数量（0/1）。

        走正常流程：探测 -> 结算 -> 递归展开，所以新目录和词表来的
        目录行为完全一致。已存在的结果不受影响。
        """
        task = Task(type="dir", name=name, parent=parent, from_="ed")
        return self.add_tasks([task])

    def add_ok_dir(self, path):
        """把一个目录认定为已存在并加入递归（od 指令用）。返回是否新增。

        与启动时 --od 的处理一致：请求目录自身 + 跳过探测直接打开递归。
        已经处理过的层会被 claim_dir 挡下，不会重复。
        """
        if self.state.is_dead_dir(path):
            self.debug("od 跳过 %r：已被判为软 404" % path)
            return False
        if path in self.state.opened:
            self.debug("od 跳过 %r：已登记过" % path)
            return False
        # 先占去重名额，保证 od 的写法优先于词表里的大小写变体
        self.state.claim_url(path, "dir", bool(self.args.cs))
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        task = Task(type="dir", name=path.rsplit("/", 1)[-1], parent=parent,
                    from_="okdir")
        if self.filter_tasks([task]):
            self.state.enqueue([task])
        self.open_dir(path, assume_ok=True)
        self.debug("od 认定存在并加入递归 %r" % path)
        return True

    def open_dir(self, dirpath, is_root=False, assume_ok=False):
        """登记一个新目录：先发探测，探测出结论后再放行常规任务。

        探测包括三种：dircheck（是否软 404）、后缀检测（每个 -s 后缀各一次）、
        备份探针（随机备份名）。常规任务全部暂存在延迟组里，等探测结算——
        否则备份的上千个任务会在后缀结论出来之前就被扫掉。

        assume_ok 为 True 时（--od 指定的目录）跳过所有探测，直接按
        「目录存在、后缀全部可用」结算并立刻放行任务。

        每个目录只登记一次（state.claim_dir 保证）。
        """
        state = self.state
        args = self.args
        if not state.claim_dir(dirpath):
            return

        # 1) 常规任务：过滤后暂存，等探测结算再放行
        common = self.filter_tasks(self.build_common_tasks(dirpath))
        state.put_group(dirpath, "common", common)

        # 2) 备份任务：同样过滤后暂存，备份探针命中才放行。
        #    这是规格里「优化实现」的关键——不探测就为每个目录发上千个请求。
        backup = self.filter_tasks(
            probes.build_backup_tasks(args, self.hostname, dirpath,
                                      self.remark_for(
                                          Task("dir", "", dirpath))))
        state.put_group(dirpath, "backup", backup)

        # --od：已知存在，不走探测，直接按「存在 + 后缀全可用」结算放行
        if assume_ok:
            state.register_probes(dirpath, 1)
            state.note_verdict(dirpath, "dead", value=False)
            self.debug("--od 直接放行目录 %r（常规 %d / 备份 %d）"
                       % (dirpath, len(common), len(backup)))
            return

        # 3) 探测任务本身：直接入队
        probe_tasks = [probes.make_dircheck_task(dirpath)]

        # 缓存命中的后缀结论要即时结算掉，它们不会再有探测任务。
        # 注意必须在 register_probes 之前收集，否则 note_verdict 会先把
        # probe_wait 减到负数，再被 register_probes 加回来，永远差几。
        cached_verdicts = []
        if args.suffixes:
            # 每个后缀各探一次。祖先目录已探明的后缀可以跳过——
            # 同一个站点后缀可用性几乎不会随目录变化。
            pending_suffixes = []
            for suffix in args.suffixes:
                cached = state.lookup_ext_cache(dirpath, suffix)
                if cached is None:
                    pending_suffixes.append(suffix)
                else:
                    cached_verdicts.append(("ext", suffix, cached))
            if pending_suffixes:
                probe_tasks.extend(
                    probes.make_suffix_probe_tasks(dirpath, pending_suffixes))

        # 每个备份后缀各探一次，判断该后缀的备份是否被服务器一律放行
        probe_tasks.extend(
            probes.make_backup_probe_tasks(dirpath, probes.BACKUP_SUFFIXES))

        # 注册「还要等几个探测结论」：入队数 + 走缓存直接结算的那几个。
        # 用实际入队数而不是构造数，避免被 --br / 去重拦下的探针永远等不到。
        state.register_probes(dirpath, len(probe_tasks) + len(cached_verdicts))
        for kind, suffix, value in cached_verdicts:
            state.note_verdict(dirpath, kind, suffix, value)

        n = self.add_tasks(probe_tasks, "probe")
        self.debug("展开目录 %r: 探测 %d 个, 暂存常规 %d / 备份 %d"
                   % (dirpath or "/", n, len(common), len(backup)))

    @property
    def hostname(self):
        from urllib.parse import urlsplit
        try:
            return urlsplit(self.args.url).hostname or self.args.url
        except Exception:
            return self.args.url

    # ------------------------------------------------------------------
    # 探测结果处理
    # ------------------------------------------------------------------
    def on_dircheck_result(self, task, url, resp):
        """dircheck 命中 => 该目录下所有路径都当作 404（软 404 服务器）。

        结论交给 note_verdict 统一结算：它会把该目录的延迟组整组作废。
        """
        state = self.state
        parent = task.parent
        if resp.exists:
            state.note_verdict(parent, "dead")
            if parent == "":
                self.printer.raw("!")
                self.printer.raw("! 根目录探测命中：目标对任意路径都返回 %s"
                                 % resp.code)
                self.printer.raw("! 无法继续扫描，终止。")
                self.printer.raw("!")
                state.stop_flag = True
                with state.lock:
                    state.cond.notify_all()
            else:
                self.printer.info("目录 %s 判定为软 404（%s -> %s），跳过其下所有路径"
                                  % (parent, url, resp.code), tag="!")
        else:
            state.note_verdict(parent, "dead", value=False)
            self.debug("dircheck 通过 %s -> %s" % (parent or "/", resp.code))

    def on_suffix_result(self, task, url, resp):
        """后缀探测命中 => 该后缀在该目录下不可信，之后不再扫。"""
        state = self.state
        suffix = "." + task.suffix
        usable = not resp.exists
        if resp.exists:
            self.printer.info("后缀 %s 在 %s 下疑似被规则放行，跳过该后缀"
                              % (suffix, task.parent or "/"), tag="!")
        else:
            self.debug("后缀探测通过 %s%s"
                       % (task.parent and task.parent + "/", suffix))
        state.note_verdict(task.parent, "ext", suffix, usable)

    def on_backup_probe_result(self, task, url, resp):
        """备份探针命中 => 该后缀的备份被服务器一律放行，跳过这个后缀。

        逐后缀判定：只作废命中的那个后缀，其他后缀照常扫。
        """
        state = self.state
        suffix = probes.backup_suffix_of(task.name, probes.BACKUP_SUFFIXES)
        if suffix is None:
            self.debug("备份探针 %s 无法识别后缀，按通过处理" % task.name)
            return
        value = not resp.exists
        if resp.exists:
            self.printer.info("备份探针 %s%s 命中（-> %s），跳过 %s 后缀的备份检测"
                              % (task.parent and task.parent + "/", suffix,
                                 resp.code, suffix), tag="!")
        else:
            self.debug("备份探针通过 %s%s"
                       % (task.parent and task.parent + "/", suffix))
        state.note_verdict(task.parent, "backup", suffix, value)

    def settle_failed_probe(self, task):
        """探测任务重试超限后，按「结论未知」结算，放行该目录的任务。

        网络不通时硬推断服务器行为很危险：如果因为网络问题就把整个目录判死，
        扫描会静默漏掉大量结果。这里只负责把延迟组解开，让常规扫描照常进行；
        目录是否存活仍由 task.parent 的 dead_dirs 判断。
        """
        if task.from_ == "dircheck":
            self.state.note_verdict(task.parent, "dead", value=False)
            self.debug("dircheck 失败 %s，按未命中处理"
                       % (task.parent or "/"))
        elif task.from_ == "suffixcheck":
            # 探测失败时保守放行：少扫的风险大于多扫
            self.state.note_verdict(task.parent, "ext", "." + task.suffix, True)
        elif task.name.startswith(probes.PROBE_PREFIX):
            # 探测失败时保守放行该后缀：少扫的风险大于多扫
            suffix = probes.backup_suffix_of(task.name, probes.BACKUP_SUFFIXES)
            if suffix is not None:
                self.state.note_verdict(task.parent, "backup", suffix, True)
            else:
                self.state.note_verdict(task.parent, "backup", None, True)
        # 这条路径不走 handle 的 is_probe 分支，得自己检查 --od 能否登记，
        # 否则根目录探测失败时 --od 目录永远不打开，整棵子树静默漏扫。
        self.maybe_open_ok_dirs()

    # ------------------------------------------------------------------
    # 递归
    # ------------------------------------------------------------------
    def expand_dir(self, task, url):
        """命中一个目录后，追加它自身的打包备份，并按 -r 决定是否继续展开。

        目录备份（admin/web/ -> admin/web.zip 等）与递归深度无关：目录已经
        确认存在，它的备份是个叶子文件，不受 -r 限制，所以放在深度判断之前。
        """
        args = self.args
        path = task.path
        self.add_dir_backup_tasks(task)

        depth = path_depth(path)
        if depth >= args.recursion:
            return
        self._dir_entry_by_name[path] = {"remark": task.remark}
        self.open_dir(path)

    def add_dir_backup_tasks(self, task):
        """目录确认存在后，把它自身的打包备份加进队列。

        如 admin/web/ 存在 -> 探 admin/web.tar.gz、admin/web.zip 等，
        from 为 backup_suffix。
        """
        dirname = task.name
        if not dirname:
            return                      # 根目录没有「自己的名字」
        tasks = probes.build_dir_backup_tasks(
            task.parent, dirname, self.remark_for(task), task.waf)
        n = self.add_tasks(tasks)
        if n:
            self.debug("目录 %s 命中，追加 %d 个自身备份任务"
                       % (task.path, n))


# ----------------------------------------------------------------------
def build(args, state, printer, ignore_rules, bypass_rules, case_filter,
          dir_entries, file_entries, files_ext_entries):
    """组装 Engine，把所有词表与索引挂上。"""
    engine = Engine(args, state, printer, ignore_rules, bypass_rules,
                    case_filter)
    engine.dir_entries = dir_entries
    engine.file_entries = file_entries
    engine.files_ext_entries = files_ext_entries
    for e in dir_entries:
        engine._dir_entry_by_name[e["name"]] = e
    return engine
