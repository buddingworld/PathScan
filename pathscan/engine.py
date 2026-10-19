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
                     WAF_FAIL_THRESHOLD, Task, path_depth, suffix_of)
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
                    self.engine.printer.raw("! task failed %s: %r"
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

        # 目录本身或其上级已被判 404：其下所有任务都不再发，探测也一样。
        # 探测被跳过时必须结算，否则该目录的延迟组永远等不到放行而卡住扫描。
        # 少了这一步，dircheck 判定软 404 之后，同批入队的后缀探针
        # 还会在一个已知的假目录里继续探，报出一堆假结论。
        # od 声明的路径例外：用户说了 dir1/dir2/dir3 存在，dir1 伪 404
        # 不该连累 dir2，链上的层照常请求。
        if (task.parent and state.is_dead_dir(task.parent)
                and task.path not in state.od_paths):
            if self.is_probe(task):
                engine.settle_failed_probe(task)
            return
        # 该目录下这个后缀被判定为不可用。备份任务也是文件任务，走同一道闸门：
        # .log 被 WAF 拦下时，后缀探测会把它标成不可信，这里就会跳过 db.log、
        # web.log 这些备份请求，而不是一遍遍撞墙。
        if task.type == "file":
            suf = suffix_of(task.name)
            if suf is not None and not state.ext_usable(task.parent, suf):
                return

        scanner = self.scanner
        scanner.sleep_interval()
        resp = scanner.fetch(url)
        state.record_request()

        # ---- 网络层失败：重试 ----
        if resp.error is not None:
            self.live(task, url, False)         # 没有状态码，标记为 [err]
            self.note_request_result(False)
            engine.waf_watch(task)          # 失败累计到阈值则纳入观察
            task.trytimes += 1
            if task.waf:
                state.waf_hit(task.name, task.waf)
            if task.trytimes > args.rt:
                state.add_error(task, url, resp.error)
                self.engine.report_error(task, url, resp.error)
                # 探测任务失败也必须结算，否则该目录的延迟组永远等不到放行
                if self.is_probe(task):
                    state.note_probe_failure(task.parent)
                self.engine.settle_failed_probe(task, resp.error)
            else:
                state.enqueue([task])
            return

        # 走到这里说明网络层是通的
        self.note_request_result(True)

        # 探测任务不参与实时日志与结果记录（它们本来就是随机路径）
        if self.is_probe(task):
            rule = engine.ignore_rules.matched(resp._resp, resp.code,
                                               resp.size)
            # --ir 命中说明这个响应就是用户定义的「不存在」（典型场景：软 404
            # 服务器统一回 200 + 固定长度的错误页）。探针必须按同一标准结算，
            # 否则 --ir 对探针完全失效——根目录 dircheck 会照样判成软 404
            # 并终止扫描，用户拿 --ir 也拦不住。
            if rule is not None:
                resp.mark_ignored()
                engine.debug("probe %s matched --ir, settled as not found" % url)
            # 同批探测里 dircheck 先回来、把该目录判成了软 404：这个在途探测
            # 的结论已经没有意义（延迟组整组作废），静默结算即可，别再报
            # 「命中 / 跳过」误导用户；根目录被判死时同样能省掉终止后的噪声。
            if state.is_dead_dir(task.parent):
                engine.settle_failed_probe(task)
                return
            if task.from_ == "dircheck":
                engine.on_dircheck_result(task, url, resp)
            else:
                engine.on_suffix_result(task, url, resp)
            # 根目录探测结算完就可以登记 --od 目录了
            engine.maybe_open_ok_dirs()
            engine.report_notices()
            return

        # ---- 忽略规则：判定为 404，与普通 404 完全一致 ----
        # 命中规则的路径不记录结果、不递归，也**不进最终报告**：软 404 站点上
        # 大部分请求都命中规则，列出来只会把报告刷爆，而它传达的信息和
        # 一行 [404] 没有区别。--debug 时才另打一行诊断。
        rule = engine.ignore_rules.matched(resp._resp, resp.code, resp.size)
        if rule is not None:
            reason = "--ir %s %s" % (rule["attr"], rule["raw"])
            self.live(task, url, False, resp.code)
            engine.debug("ignored %s (%s)" % (url, reason))
            return

        exists = resp.exists
        if not exists:
            self.live(task, url, False, resp.code)
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
        self.live(task, url, True, resp.code)
        if task.waf:
            state.waf_hit(task.name, task.waf)

        # ---- 递归 ----
        if task.type == "dir":
            engine.expand_dir(task, url)

    @staticmethod
    def is_probe(task):
        """是否是探测任务（dircheck / 后缀检测）。"""
        return task.from_ in ("dircheck", "suffixcheck")

    def live(self, task, url, ok, code=None):
        """打一条实时日志（带状态码、速度与备注）。只输出到屏幕，不写 --of。

        code 为 None 表示网络层失败，此时标记为 [err]；有状态码就显示
        状态码本身（[200] / [404]），比笼统的 [err] 有用得多。

        remark 的显示门控在 Printer.live_line 里（只在 ok 时显示），
        这里照常把备注传进去即可。
        """
        self.engine.printer.live_line(self.thread_id, task.path, ok,
                                      self.engine.state.speed(),
                                      self.engine.remark_for(task), code)

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
                "thread %d: %d failures in a row, pausing %.0fs"
                % (self.thread_id, n, THREAD_FAIL_PAUSE), tag="!")
            if self._sleep_interruptible(THREAD_FAIL_PAUSE):
                return                      # 被终止/惩罚期间收到指令

            if state.all_other_threads_idle(self.thread_id):
                # 所有线程都在暂停 -> IP 大概率被封，转 WAF 等待模式
                self.engine.printer.info(
                    "all threads paused after failures, IP likely blocked, "
                    "entering WAF wait mode", tag="!")
                state.waf_request_wait()
            else:
                self.engine.printer.info(
                    "thread %d resumed (other threads are healthy)"
                    % self.thread_id, tag="*")
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
        self._probe_suffixes = None
        # --od 的延迟登记状态（见 start / maybe_open_ok_dirs）
        self._ok_dirs_pending = []
        self._ok_dirs_done = True

    # ------------------------------------------------------------------
    def report_notices(self):
        """打印结算期间攒下的一次性提示（如「整批探针全挂」）。"""
        for line in self.state.pop_notices():
            self.printer.info(line, tag="!")

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
            self.debug("WAF watch: %s (%d failures)" % (task.name, task.trytimes))

    def waf_sweep(self):
        """周期性统计观察窗口，把孤立的失败名称加入忽略列表。

        窗口到点后：只有它自己 -> 判定该名称触发 WAF，加入忽略列表；
        还有别的名称 -> 只移除当前项（说明是站点普遍问题，不是这个名称）。
        """
        blocked, dropped = self.state.waf_collect_due()
        for name in blocked:
            self.printer.info("WAF check: name %r added to the ignore list, "
                              "no longer tested" % name, tag="!")
        for name in dropped:
            self.debug("WAF watch: %s dropped (other names failed too)" % name)
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
            # 上级目录被拉黑/忽略：整棵子树都不再发请求
            if state.path_under_blocked(path):
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
                self.debug("dedup skipped %s" % task.path)
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
        # 等根目录结算后再打开 --od 目录：它们要先登记进 od 链，
        # 链上的层才不会被别的软 404 判定挡住。
        self._ok_dirs_pending = list(args.ok_dirs)
        self.state.od_paths.update(args.ok_dirs)
        self._ok_dirs_done = not self._ok_dirs_pending
        self.maybe_open_ok_dirs()

        with state.lock:
            self.printer.info("queue ready, starting %d thread(s)..." % args.thread)
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
        self.debug("root probes settled (probe_wait=%s), registering --od dirs"
                   % (waiting or "empty"))
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

        名字两端的斜杠先去掉：``ed admin/`` 这种写法会带着尾斜杠进来，
        命中后加后缀会拼出 ``admin/.zip`` 这种空文件名路径。
        """
        name = str(name).strip("/")
        if not name:
            return 0
        task = Task(type="dir", name=name, parent=parent, from_="ed")
        return self.add_tasks([task])

    def add_ok_dir(self, path):
        """把一个目录认定为已存在并加入递归（od 指令用）。返回是否新增。

        与启动时 --od 的处理一致：请求目录自身 + 登记递归。已经处理过的层
        会被 claim_dir 挡下，不会重复。

        od 链上的层即使被自己的 dircheck 判成软 404，也要继续往下打开：
        用户明确说了 dir1/dir2/dir3 存在，dir1 是伪 404 不该连累 dir2。
        被跳过的是该层自己的词表子目录（由延迟组统一作废）。
        """
        dead = self._dead_ancestor_outside_od(path)
        if dead is not None:
            self.debug("od skip %r: %r is a soft 404" % (path, dead))
            return False
        if path in self.state.opened:
            self.debug("od skip %r: already registered" % path)
            return False
        self.state.od_paths.add(path)
        # 先占去重名额，保证 od 的写法优先于词表里的大小写变体
        self.state.claim_url(path, "dir", bool(self.args.cs))
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        task = Task(type="dir", name=path.rsplit("/", 1)[-1], parent=parent,
                    from_="okdir")
        # 该名字已在 --ed 列表里（--od 的段名会自动并进去）时不重复发请求：
        # 那条 --ed 任务会照常请求这个路径，且走完整的探测与递归。
        if path in self.args.ed_list:
            self.debug("od %r 已由 --ed 覆盖，不再单独请求" % path)
        elif self.filter_tasks([task]):
            self.state.enqueue([task])
        self.open_dir(path, assume_ok=True)
        self.debug("od registered %r as existing, recursing" % path)
        return True

    def _dead_ancestor_outside_od(self, path):
        """path 自身或某个上级被判软 404，且该层不在 od 链上。返回该层。

        od 声明的层是用户明确指定存在的，被判软 404 也不阻断链：
        ``--od dir1/dir2/dir3`` 里 dir1 伪 404 时，dir2 仍要继续扫。
        只有链外的上级被判死（例如根目录整体是软 404）才放弃。
        """
        state = self.state
        with state.lock:
            if not state.dead_dirs:
                return None
            for anc in [path] + ancestors(path):
                if anc in state.dead_dirs and anc not in state.od_paths:
                    return anc
        return None

    def open_dir(self, dirpath, is_root=False, assume_ok=False):
        """登记一个新目录：先发探测，探测出结论后再放行常规任务。

        探测包括两种：dircheck（是否软 404）与后缀检测（每个 -s 后缀各一次）。
        常规任务全部暂存在延迟组里，等探测结算——否则备份的上千个任务会在
        后缀结论出来之前就被扫掉。

        assume_ok 为 True 时（--od / od 指令指定的目录）跳过后缀探测，
        但仍发一次 dircheck：od 路径也可能落在伪 404 区里，那种目录不该
        把整份词表都扫一遍。结论只决定「要不要展开它的词表子目录」，
        od 链本身照走（见 _dead_ancestor_outside_od）。

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
        #    --nb 时整块跳过：不生成备份任务也不发备份探针（见下面第 3 步），
        #    这样连「暂存后无探针可等」这种半吊子状态都不会出现。
        backup = []
        if not args.nb:
            backup = self.filter_tasks(
                probes.build_backup_tasks(args, self.hostname, dirpath,
                                          self.remark_for(
                                              Task("dir", "", dirpath))))
            state.put_group(dirpath, "backup", backup)

        # --od：用户已确认这层存在，后缀全按可用处理，但仍探一次 dircheck。
        # 伪 404 区里的 od 路径（dir1 命中但 dir1/xx1、dir1/xx2 全是假 200）
        # 不该把整份词表都扫一遍；结论只作废它的词表子目录，od 链照走。
        if assume_ok:
            task = probes.make_dircheck_task(dirpath)
            state.register_probes(dirpath, 1)
            if not self.add_tasks([task], "probe"):
                # 探针没入队（被 --br / 去重拦下）就即时结算，
                # 否则这层的延迟组永远等不到放行
                state.note_verdict(dirpath, "dead", value=False)
            self.debug("--od registered %r (common %d / backup %d), waiting "
                       "for dircheck" % (dirpath, len(common), len(backup)))
            return

        # 3) 探测任务本身：直接入队
        probe_tasks = [probes.make_dircheck_task(dirpath)]

        # 缓存命中的后缀结论要即时结算掉，它们不会再有探测任务。
        # 注意必须在 register_probes 之前收集，否则 note_verdict 会先把
        # probe_wait 减到负数，再被 register_probes 加回来，永远差几。
        cached_verdicts = []
        pending_suffixes = []
        for suffix in self.probe_suffixes:
            # 每个后缀各探一次。祖先目录已探明的后缀可以跳过——
            # 同一个站点后缀可用性几乎不会随目录变化。
            cached = state.lookup_ext_cache(dirpath, suffix)
            if cached is None:
                pending_suffixes.append(suffix)
            else:
                cached_verdicts.append(("ext", suffix, cached))
        if pending_suffixes:
            probe_tasks.extend(
                probes.make_suffix_probe_tasks(dirpath, pending_suffixes))

        # 注册「还要等几个探测结论」：入队数 + 走缓存直接结算的那几个。
        # 用实际入队数而不是构造数，避免被 --br / 去重拦下的探针永远等不到。
        state.register_probes(dirpath, len(probe_tasks) + len(cached_verdicts))
        for kind, suffix, value in cached_verdicts:
            state.note_verdict(dirpath, kind, suffix, value)

        n = self.add_tasks(probe_tasks, "probe")
        self.debug("opened %r: %d probes, %d common / %d backup staged"
                   % (dirpath or "/", n, len(common), len(backup)))

    @property
    def hostname(self):
        from urllib.parse import urlsplit
        try:
            return urlsplit(self.args.url).hostname or self.args.url
        except Exception:
            return self.args.url

    @property
    def probe_suffixes(self):
        """本轮要逐个探测的后缀（按出现顺序去重，只算一次）。

        三类来源缺一不可：
        * ``-s`` 列出的后缀 —— 常规文件任务会按它们展开；
        * ``--files`` 词表里出现的后缀 —— 那些名字自带后缀，不经过 -s；
        * 备份文件后缀（``db.zip`` / ``web.log`` …）—— 备份任务同样是
          文件任务，走同一套「这个后缀在这台服务器上可不可信」的判断。
          只探 -s 的后缀，会让 .log 这类备份后缀整轮都没被验证过：
          被 WAF 拦下的请求会一遍遍重复发。

        祖先目录已探明的后缀会走缓存，不会重复探（同一站点后缀可用性
        几乎不随目录变化）。
        """
        if self._probe_suffixes is None:
            out = []
            for suffix in self.args.suffixes:
                if suffix not in out:
                    out.append(suffix)
            for entry in self.files_ext_entries:
                suffix = suffix_of(entry.get("name", ""))
                if suffix is not None and suffix not in out:
                    out.append(suffix)
            # --nb 不生成任何备份任务，备份后缀也就不必探
            if not self.args.nb:
                for suffix in probes.BACKUP_SUFFIXES:
                    if suffix not in out:
                        out.append(suffix)
            self._probe_suffixes = out
        return self._probe_suffixes

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
            # 该目录（及其下所有路径）此前记录的命中都是这个假目录的产物，
            # 撤回并转入 Ignored Paths —— 否则它们会以「存在」的姿态留在
            # 结果里，用户会看到一堆已被 dircheck 判死的子目录。
            withdrawn = state.withdraw_dead_results(parent)
            if parent == "":
                self.printer.raw("!")
                self.printer.raw("! root dircheck hit: the target answers %s "
                                 "for any path" % resp.code)
                # 终止前把触发终止的这次请求（关键请求）的响应关键信息打出来：
                # 只有「终止」没有证据，用户无法判断服务器到底回了什么
                # （真软 404 / WAF 拦截页 / 代理注入），也就无从排查。
                self.printer.raw("! key request: %s %s"
                                 % (self.args.method.upper(), resp.url))
                self.printer.raw("! key response: %s" % resp.key_info())
                self.printer.raw("! cannot continue, stopping.")
                self.printer.raw("!")
                state.stop_flag = True
                with state.lock:
                    state.cond.notify_all()
            else:
                # 一行说清：哪个目录被判定为软 404、依据是哪次探测、
                # 服务器回的什么。完整 URL 在这里是噪音，路径足够定位。
                msg = ("/%s soft 404 for /%s code:%s len:%s"
                       % (parent, task.path, resp.code, resp.size))
                if withdrawn:
                    msg += ", withdrew %d result(s)" % withdrawn
                self.printer.info(msg, tag="!")
        else:
            state.note_verdict(parent, "dead", value=False)
            self.debug("dircheck passed %s -> %s" % (parent or "/", resp.code))

    def on_suffix_result(self, task, url, resp):
        """后缀探测命中 => 该后缀在该目录下不可信，之后不再扫。

        命中不限于 200：随机名 + 该后缀只要没被当成「不存在」（404 类），
        就说明这个后缀的响应不可信——可能是万能 200，也可能是 WAF 对
        这类后缀一律 403。两种情况的处理一样：该后缀整轮跳过，别再拿
        备份名一遍遍去撞。
        """
        state = self.state
        suffix = suffix_of(task.name)
        if suffix is None:
            self.debug("suffix probe %s: no suffix, ignored" % task.name)
            return
        usable = not resp.exists
        if resp.exists:
            self.printer.info("suffix %s under %s is untrustworthy (code:%s), "
                              "skipping it"
                              % (suffix, task.parent or "/", resp.code), tag="!")
        else:
            self.debug("suffix probe passed %s%s"
                       % (task.parent and task.parent + "/", suffix))
        state.note_verdict(task.parent, "ext", suffix, usable)

    def settle_failed_probe(self, task, reason=""):
        """探测任务重试超限后结算，放行该目录的任务。

        目录探测失败时按「未命中」处理：网络不通不能硬推断服务器行为，
        把整个目录判死会静默漏掉大量结果。目录是否存活仍由 task.parent
        的 dead_dirs 判断。

        后缀探测失败则相反，判为**不可信**：WAF 对 .log / .env 这类后缀
        常常直接断连而不是回 403，探针被断连就是「这个后缀发不得」的信号。
        判不可信后该后缀整轮跳过，备份名不会一遍遍撞墙；结论也会沿目录树
        复用，所以一次失败不会在每个子目录重演。
        """
        if task.from_ == "dircheck":
            self.state.note_verdict(task.parent, "dead", value=False)
            self.debug("dircheck failed %s, treated as not hit"
                       % (task.parent or "/"))
        elif task.from_ == "suffixcheck":
            suffix = suffix_of(task.name)
            if suffix is not None:
                self.printer.info("suffix %s under %s: probe failed (%s)"
                                  % (suffix, task.parent or "/",
                                     reason or "no response"), tag="!")
                # 标成「失败得出的结论」：整批探针全挂时会撤销它
                self.state.mark_ext_failed(task.parent, suffix)
                self.state.note_verdict(task.parent, "ext", suffix, False)
        # 这条路径不走 handle 的 is_probe 分支，得自己检查 --od 能否登记，
        # 否则根目录探测失败时 --od 目录永远不打开，整棵子树静默漏扫。
        self.maybe_open_ok_dirs()
        self.report_notices()

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
        from 为 backup_suffix。--nb 关闭所有自动备份路径，这里直接跳过。

        标注了 ``waf`` 的目录额外跳过：备份名带着同一个敏感串
        （``.svn`` -> ``.svn.zip``、``.svn.bak``），照样会触发那条 WAF
        规则。而 WAF 打回的 403 等状态码不在「不存在」之列，会被记成
        命中，白扫一堆假结果还继续喂检测规则。该目录本身已计入结果，
        少了备份不会漏掉它存在的证据。

        判据是「条目标了 waf」而不是「已被拉黑」：waf 是阈值，要超过才
        拉黑（``waf=1`` 得失败两次），第一次命中时名字还在白名单里，
        按拉黑判断会漏掉。
        """
        if self.args.nb:
            return
        if task.waf:
            self.debug("dir %s is marked waf, skipping its backups %s.*"
                       % (task.path, task.name))
            return
        dirname = task.name
        if not dirname:
            return                      # 根目录没有「自己的名字」
        tasks = probes.build_dir_backup_tasks(
            task.parent, dirname, self.remark_for(task), task.waf)
        n = self.add_tasks(tasks)
        if n:
            self.debug("dir %s hit, queued %d self backup task(s)"
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
