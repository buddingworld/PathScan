# -*- coding: utf-8 -*-
"""PathScan 的数据模型：队列任务 Task 与跨线程共享状态 GlobalState。

设计要点
--------
* Task 严格对应规格里的 7 个 JSON 字段，可无损 to_dict / from_dict 往返。
* 所有跨线程可变状态集中在 GlobalState，统一用一把 RLock + Condition 保护。
* pending 计数 = 「队列中 + 正在请求 + 等待探测完成」的任务总数。只有 pending
  归零才算扫描结束；否则某个目录的探测任务还在飞，队列却是空的，会被误判成
  已经扫完而提前退出。
"""

import random
import string
import threading
import time

_RAND_CHARS = string.ascii_lowercase + string.digits

# 备份探针的固定名前缀（probes.py 用它生成探针名）。
# 放在 models 里是因为任务优先级要按它判断，而 models 不能反向依赖 probes。
PROBE_PREFIX = "__probe__"

# ----------------------------------------------------------------------
# 任务优先级：数字越小越先执行
# ----------------------------------------------------------------------
# 探测任务必须最先跑：它们决定延迟组什么时候放行，排在后面会互相卡死。
PRIO_PROBE = 0
# 目录其次：先把整棵目录树铺完，才能发现所有子目录。
PRIO_DIR = 1
# 文件最后：等目录都扫完了再集中扫。
PRIO_FILE = 2

PRIO_NAMES = {PRIO_PROBE: "探测", PRIO_DIR: "目录", PRIO_FILE: "文件"}

# 速度滑动窗口的桶数。速度 = 窗口内请求数 / SPEED_WINDOW，
# 用 1 秒一个桶，所以这个值同时也是窗口的秒数。
SPEED_WINDOW = 10

# 线程连续失败到该次数就惩罚性暂停
THREAD_FAIL_LIMIT = 5
THREAD_FAIL_PAUSE = 30.0

# 一个 name 连续失败到该次数就进入 WAF 观察窗口
WAF_FAIL_THRESHOLD = 2
# 观察窗口时长（秒）：窗口结束时若只有它自己，就拉黑
WAF_WINDOW_SECONDS = 5.0

# WAF 拦截等待模式：无按键超过该时长视为无人值守，自动恢复
WAF_IDLE_RESUME = 30 * 60.0


def rand_token(n=8):
    """生成 n 位随机小写字母数字串，用于探测服务器是否存在「万能 200」。"""
    return "".join(random.choice(_RAND_CHARS) for _ in range(n))


def join_path(parent, name):
    """拼接上层路径与当前名称。"""
    return name if not parent else parent + "/" + name


def path_depth(path):
    """路径深度：根目录 "" 为 0，admin 为 1，admin/backend 为 2。"""
    return 0 if not path else path.count("/") + 1


def ancestors(path):
    """由浅到深返回 path 的所有上级目录（不含自身）。"""
    parts = path.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


class Task(object):
    """队列中的一个待扫描路径。

    对应规格里的 JSON：:

        {"type":"dir","trytimes":0,"name":"admin","parent":"",
         "from":"dircheck","remark":"","waf":3}

    ``from_`` 在 Python 侧带下划线（from 是关键字），序列化时仍用 ``from``。
    """

    __slots__ = ("type", "trytimes", "name", "parent", "from_", "remark", "waf",
                 "depth_lo", "depth_hi")

    def __init__(self, type="dir", name="", parent="", from_="common",
                 remark="", waf=0, trytimes=0, depth_lo=0, depth_hi=None):
        self.type = type
        self.trytimes = trytimes
        self.name = name
        self.parent = parent
        self.from_ = from_
        self.remark = remark
        self.waf = waf
        # 该条目允许出现的层级区间（来自备注的 "r"），hi=None 表示不设上限
        self.depth_lo = depth_lo
        self.depth_hi = depth_hi

    @property
    def path(self):
        """相对根目录的路径，例如 management/backend。"""
        return join_path(self.parent, self.name)

    @property
    def depth(self):
        """递归深度，按规格用 ``parent.count("/") + 1`` 计算。

        注意这个值对「根目录下的项」和「一级子目录下的项」都是 1，因为
        parent 分别是 ``""`` 和 ``"admin"``。用于 ``-r`` 的层数判断时它是
        按规格对齐的；用于备注里的 ``r`` 层级判断请用 :attr:`path_depth`。
        """
        return self.parent.count("/") + 1

    @property
    def path_depth(self):
        """该条目所在目录的层级：根目录为 1，``/xx`` 为 2，``/xx/yy`` 为 3。

        规格里 ``"r":"0-1"`` 表示「仅在 0-1 层目录中测试」，
        ``/test`` 是一层、``/xx/test`` 是两层，所以这里按实际目录深度算。
        """
        return 1 if not self.parent else self.parent.count("/") + 2

    def depth_allowed(self):
        """当前层级是否在该条目的允许区间内。

        规格写 ``"r":"0-1"`` 时，``/test``（1 层）与根目录（0 层）测试，
        ``/xx/test``（2 层）不测试，所以比较用的是 :attr:`path_depth`。
        """
        d = self.path_depth
        if d < self.depth_lo:
            return False
        if self.depth_hi is not None and d > self.depth_hi:
            return False
        return True

    @property
    def suffix(self):
        """文件后缀，按规格取 ``name.rsplit(".", 1)[-1]``。"""
        return self.name.rsplit(".", 1)[-1]

    def clone(self):
        return Task(self.type, self.name, self.parent, self.from_,
                    self.remark, self.waf, self.trytimes,
                    self.depth_lo, self.depth_hi)

    def to_dict(self):
        return {
            "type": self.type,
            "trytimes": self.trytimes,
            "name": self.name,
            "parent": self.parent,
            "from": self.from_,
            "remark": self.remark,
            "waf": self.waf,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            type=d.get("type", "dir"),
            name=d.get("name", ""),
            parent=d.get("parent", ""),
            from_=d.get("from", "common"),
            remark=d.get("remark", ""),
            waf=int(d.get("waf", 0) or 0),
            trytimes=int(d.get("trytimes", 0) or 0),
        )

    def __repr__(self):
        return "<Task %s %s from=%s try=%d>" % (
            self.type, self.path, self.from_, self.trytimes)


def task_priority(task):
    """任务优先级：探测 < 目录 < 文件。

    探测任务最高，因为它们决定延迟组何时放行；若排在目录/文件后面，
    目录任务会一直等探测结论，而探测任务又排在它们后面 —— 直接死锁。

    目录优先于文件，这样整棵目录树先铺开，文件最后集中扫。
    """
    if task.from_ in ("dircheck", "suffixcheck"):
        return PRIO_PROBE
    if task.from_ == "backup" and task.name.startswith(PROBE_PREFIX):
        return PRIO_PROBE
    return PRIO_DIR if task.type == "dir" else PRIO_FILE


class TaskQueue(object):
    """按优先级分层的任务队列，对外暴露 add/extend/pop 接口。

    规格里的 exec 示例是 ``test_list.add(123)``，所以队列必须有 add()。
    同时为了让 exec 塞进来的裸值不会让调度器崩，add/extend 会把非 Task 值
    包装成 Task。

    内部按 PRIO_* 分成几个 FIFO 桶，出队时先掏优先级最高的非空桶。
    这样只需在入队时分一次桶，出队是 O(1)，也不必每次排序。
    """

    def __init__(self):
        # 每个优先级一个 FIFO 桶
        self.buckets = {}
        self.count = 0

    # ---- 内部 ----
    def _bucket(self, prio):
        b = self.buckets.get(prio)
        if b is None:
            b = self.buckets[prio] = _FifoBucket()
        return b

    # ---- 对外接口 ----
    def add(self, item, priority=None):
        task = _coerce_task(item)
        prio = task_priority(task) if priority is None else priority
        self._bucket(prio).add(task)
        self.count += 1

    def extend(self, items):
        for item in items:
            self.add(item)

    def empty(self):
        return self.count <= 0

    def qsize(self):
        return self.count

    def pop_nowait(self):
        """取一个任务：按优先级从高到低找第一个非空桶。"""
        if self.count <= 0:
            return None
        for prio in sorted(self.buckets):
            b = self.buckets[prio]
            if not b.empty():
                task = b.pop_nowait()
                self.count -= 1
                return task
        return None

    def peek_priority(self):
        """看一眼下一个任务的优先级（不出队）。空队列返回 None。"""
        if self.count <= 0:
            return None
        for prio in sorted(self.buckets):
            if not self.buckets[prio].empty():
                return prio
        return None

    def counts(self):
        """各优先级的待处理数量，status 里用。"""
        return dict((prio, b.qsize())
                    for prio, b in self.buckets.items() if not b.empty())

    def __len__(self):
        return self.count

    def __iter__(self):
        """允许遍历待处理任务（exec / status 里会用到），按优先级顺序。"""
        out = []
        for prio in sorted(self.buckets):
            out.extend(self.buckets[prio])
        return iter(out)

    def __repr__(self):
        return "<TaskQueue %d 待处理 %s>" % (self.count, self.counts())


class _FifoBucket(object):
    """一个先进先出的桶，用头指针避免 pop(0) 的 O(n)。"""

    def __init__(self):
        self.items = []
        self.head = 0

    def add(self, task):
        self.items.append(task)

    def empty(self):
        return self.head >= len(self.items)

    def qsize(self):
        return len(self.items) - self.head

    def pop_nowait(self):
        if self.empty():
            return None
        item = self.items[self.head]
        self.items[self.head] = None
        self.head += 1
        # 积压太多时压缩一次，回收前面的空位
        if self.head > 512 and self.head * 2 > len(self.items):
            del self.items[:self.head]
            self.head = 0
        return item

    def __iter__(self):
        return iter(self.items[self.head:])


def _coerce_task(item):
    """exec 可能往队列里塞任意值，统一成 Task 以免调度器崩。

    规格的示例是 ``test_list.add(123)``——把值当成目录名处理，
    所以 123 会变成扫描 ``/123``。传 dict 则按 Task 的 JSON 字段解析。
    """
    if isinstance(item, Task):
        return item
    if isinstance(item, dict):
        task = Task.from_dict(item)
        if not task.from_ or task.from_ == "common":
            task.from_ = "exec"
        return task
    return Task(type="dir", name=str(item), from_="exec")


class GlobalState(object):
    """扫描器的全部共享状态。谁改字段谁持锁，避免时序竞争。"""

    def __init__(self, args):
        self.args = args

        # ---- 任务队列与计数 ----
        self.lock = threading.RLock()
        self.cond = threading.Condition(self.lock)
        self.queue = TaskQueue()
        self.pending = 0           # 未完成任务总数（队列 + 在跑 + 等探测）
        self.active = 0            # 正在发请求的线程数
        self.done = 0              # 已处理完的任务数
        self.inflight_dirs = 0     # 正在请求中的探测/目录任务数（用于目录阶段判定）

        # ---- 探测结论 ----
        self.dead_dirs = set()             # 判定为 404 的目录路径（前缀语义）
        self.ext_probe = {}                # (dirpath, ext) -> True=可用 / False=不可信
        self.opened = set()                # 已经登记过探测任务的目录
        # 延迟任务组：一个目录的常规任务要等该目录的全部探测出结论才放行，
        # 否则会在「后缀还没探完」时就把该后缀的任务扫掉。
        self.groups = {}                   # dirpath -> {key: [Task]}
        self.probe_wait = {}               # dirpath -> 未完成的探测数
        self.verdicts = {}                 # dirpath -> {"dead":bool,"exts":{suf:bool}}

        # ---- WAF 与过滤 ----
        self.name_waf_count = {}           # name -> 命中次数（失败与「正常」都算）
        self.name_blocked = set()          # 超过阈值后全局拉黑的 name
        self.suppressed = []               # rp 指令登记的「前缀移除」列表
        self.seen_urls = set()             # (url, type) 去重，防菱形递归重复入队
        self.seen_ci = set()               # --cs 0 时用的不分大小写去重集合

        # ---- 结果 ----
        self.results = []                  # 命中的结果
        self.ignored = []                  # 被视为 404 而忽略的路径
        self.errors = []                   # 重试超限的失败路径
        self.reported = set()              # (url, type) 已输出

        # ---- 控制 ----
        self.stop_flag = False
        self.pause_requested = False
        self.pause_event = threading.Event()
        self.pause_event.set()             # set = 运行中，clear = 暂停
        self.threads_alive = 0
        self.target_threads = args.thread
        self.retire = 0                    # 需要退出的线程数（at 减线程用）
        self.last_activity = time.time()
        self.start_time = time.time()

        # ---- 线程健康度（连续失败计数） ----
        self.thread_fails = {}             # thread_id -> 连续失败次数
        self.thread_alive_ids = set()      # 活着的 thread_id
        self.thread_paused = set()         # 正在 30s 惩罚中的 thread_id

        # ---- WAF 自动检测 ----
        # name -> 计入计数的时刻；5 秒后统计，只有它自己就拉黑
        self.waf_window = {}
        self.waf_ignored = []              # 被判定为 WAF 敏感而加入忽略列表的 name
        self.bypass_names = set()          # 忽略列表（WAF 判定加入的）
        self.waf_wait_requested = False    # 请求进入 WAF 拦截等待模式
        self.waf_waiting = False           # 当前正处于该模式
        self.waf_wait_until = 0.0

        # ---- 速度统计 ----
        # 用 10 个 1 秒的桶做滑动窗口，速度 = 窗口内请求数 / 10。
        # 单独一把锁，避免和队列锁互相争用。
        self.stat_lock = threading.Lock()
        self.req_buckets = [0] * SPEED_WINDOW
        self.req_last_sec = int(time.time())
        self.req_total = 0

    # ------------------------------------------------------------------
    # 队列
    # ------------------------------------------------------------------
    def enqueue(self, tasks):
        """批量入队并唤醒等待的线程。"""
        if not tasks:
            return
        with self.cond:
            if self.stop_flag:
                return
            self.queue.extend(tasks)
            self.pending += len(tasks)
            self.cond.notify_all()

    def take(self):
        """取一个任务。

        目录阶段未结束时不会返回文件任务 —— 这样整棵目录树先铺完，
        文件最后集中扫。返回 None 表示确实没活了，可以退出。
        """
        with self.cond:
            while not self.stop_flag:
                if not self.queue.empty():
                    prio = self.queue.peek_priority()
                    # 目录阶段没结束就先把文件压住，等目录扫完
                    if prio >= PRIO_FILE and not self.dir_phase_done():
                        self.cond.wait(0.2)
                        continue
                    task = self.queue.pop_nowait()
                    self.active += 1
                    # 探测与目录任务都可能带来新的目录，计入在途
                    if task_priority(task) < PRIO_FILE:
                        self.inflight_dirs += 1
                    self.last_activity = time.time()
                    return task
                if self.pending <= 0:
                    return None
                self.cond.wait(0.2)
            return None

    def dir_phase_done(self):
        """目录阶段是否结束：没有待处理目录、没有在途目录/探测、没有未结算探测。

        三个条件缺一不可：
        * 队列里没有目录任务（含刚发现还没跑的）
        * 没有正在请求中的目录/探测任务（它们可能展开出新目录）
        * 没有等待结算的探测（结算时会放行新的目录任务）
        """
        if not self.queue.empty() and self.queue.peek_priority() < PRIO_FILE:
            return False
        if self.inflight_dirs > 0:
            return False
        if self.probe_wait:
            return False
        return True

    def complete(self, task=None):
        """任务处理完毕（无论成功失败）。"""
        with self.cond:
            self.active -= 1
            self.pending -= 1
            self.done += 1
            if task is not None and task_priority(task) < PRIO_FILE:
                self.inflight_dirs -= 1
            self.last_activity = time.time()
            self.cond.notify_all()

    def pending_count(self):
        with self.lock:
            return self.pending

    def is_finished(self):
        with self.lock:
            return self.pending <= 0

    # ------------------------------------------------------------------
    # 去重
    # ------------------------------------------------------------------
    def claim_url(self, url, type_, case_sensitive=True):
        """登记该 url 已被扫描。返回 True 表示这次是首次登记。"""
        with self.lock:
            if case_sensitive:
                key = (url, type_)
                if key in self.seen_urls:
                    return False
                self.seen_urls.add(key)
                return True
            key = (url.lower(), type_)
            if key in self.seen_ci:
                return False
            self.seen_ci.add(key)
            return True

    # ------------------------------------------------------------------
    # 探测
    # ------------------------------------------------------------------
    def claim_dir(self, dirpath):
        """认领一个新目录的探测权。只有第一个调用者会拿到 True。"""
        with self.lock:
            if dirpath in self.opened:
                return False
            self.opened.add(dirpath)
            return True

    def mark_dead_dir(self, dirpath):
        with self.lock:
            self.dead_dirs.add(dirpath)

    def is_dead_dir(self, dirpath):
        """目录本身，或它的任一上级被判 404，都算死。"""
        with self.lock:
            if not self.dead_dirs:
                return False
            if dirpath in self.dead_dirs:
                return True
            for a in ancestors(dirpath):
                if a in self.dead_dirs:
                    return True
            return False

    def ext_usable(self, dirpath, ext):
        """后缀在该目录下是否可信。未探测过则返回 True（宁可多扫）。"""
        with self.lock:
            return self.ext_probe.get((dirpath, ext), True)

    def lookup_ext_cache(self, dirpath, ext):
        """沿上级目录回溯，找已探明的同后缀结论。返回 None 表示没缓存。"""
        with self.lock:
            cur = dirpath
            while True:
                got = self.ext_probe.get((cur, ext))
                if got is not None:
                    return got
                if not cur:
                    return None
                cur = cur.rsplit("/", 1)[0] if "/" in cur else ""

    def set_ext_probe(self, dirpath, ext, usable):
        with self.lock:
            self.ext_probe[(dirpath, ext)] = usable

    # ------------------------------------------------------------------
    # 延迟任务组与探测结算
    # ------------------------------------------------------------------
    def put_group(self, dirpath, key, tasks):
        """暂存一批延迟任务（不计入 pending，因此不会被当成待办）。"""
        with self.lock:
            self.groups.setdefault(dirpath, {})[key] = tasks

    def register_probes(self, dirpath, count):
        with self.lock:
            self.probe_wait[dirpath] = self.probe_wait.get(dirpath, 0) + count
            self.verdicts.setdefault(dirpath, {"dead": False, "exts": {}})

    def note_verdict(self, dirpath, kind, key=None, value=None):
        """记录一条探测结论。返回本次结算后要放行的任务列表（可能为空）。

        结算放在锁内完成：先把要放行的任务计入 pending，再从 groups 摘掉，
        这样别的线程不会在「队列已空」的窗口里误判扫描结束。
        """
        with self.lock:
            verdict = self.verdicts.setdefault(
                dirpath, {"dead": False, "exts": {}, "backup": None})
            if kind == "dead":
                # value=False 表示 dircheck 通过（该目录不是软 404）。
                # 只有明确命中才算死目录，漏掉这个判断会把每个目录都判死。
                if value is not False:
                    verdict["dead"] = True
                    self.dead_dirs.add(dirpath)
            elif kind == "backup":
                verdict["backup"] = value
            elif kind == "ext":
                verdict["exts"][key] = value
                self.ext_probe[(dirpath, key)] = value

            self.probe_wait[dirpath] = self.probe_wait.get(dirpath, 1) - 1
            if self.probe_wait[dirpath] > 0:
                return []
            self.probe_wait.pop(dirpath, None)

            groups = self.groups.pop(dirpath, None)
            if not groups:
                self.cond.notify_all()
                return []

            released = self._select_releasable(groups, verdict)
            if released:
                self.queue.extend(released)
                self.pending += len(released)
            self.cond.notify_all()
            return released

    @staticmethod
    def _select_releasable(groups, verdict):
        """按探测结论过滤出可以放行的任务。

        放行顺序很重要：先 common 后 backup。备份任务一个目录就有上千个
        （37 名称 × 32 后缀），如果它们排在词表条目前面，扫描前期看到的
        全是备份名，用户指定的词表要很久才轮到。
        """
        # 目录被判软 404：该目录下所有任务全部作废
        if verdict.get("dead"):
            return []

        ext_ok = verdict.get("exts") or {}
        backup_ok = verdict.get("backup")
        released = []

        # common 优先，之后才是 backup
        keys = [k for k in ("common", "backup") if k in groups]
        keys.extend(k for k in list(groups.keys()) if k not in keys)

        for key in keys:
            tasks = groups.pop(key)
            # 备份探针命中（随机备份名居然存在）说明服务器对备份类路径放行，
            # 检测失去意义，整组丢掉
            if key == "backup" and backup_ok is False:
                continue
            for task in tasks:
                if key == "common" and task.type == "file" and "." in task.name:
                    suffix = "." + task.name.rsplit(".", 1)[-1]
                    if ext_ok.get(suffix) is False:
                        continue
                released.append(task)
        return released

    # ------------------------------------------------------------------
    # WAF 名称计数
    # ------------------------------------------------------------------
    def waf_hit(self, name, threshold):
        """名称命中一次。失败与「返回正常」都计入，任一超阈值即全局拉黑。

        规格里阈值 ``waf`` 默认 0，表示不检测。
        """
        if not threshold:
            return False
        with self.lock:
            if name in self.name_blocked:
                return True
            n = self.name_waf_count.get(name, 0) + 1
            self.name_waf_count[name] = n
            if n > threshold:
                self.name_blocked.add(name)
                return True
            return False

    def is_name_blocked(self, name):
        with self.lock:
            return name in self.name_blocked

    # ------------------------------------------------------------------
    # 结果
    # ------------------------------------------------------------------
    def suppress(self, prefix):
        """rp 指令：登记一个要移除的前缀，并立即清掉已有结果。"""
        with self.lock:
            self.suppressed.append(prefix)
            removed = [r for r in self.results if r["path"].startswith(prefix)]
            self.results = [r for r in self.results
                            if not r["path"].startswith(prefix)]
            self.errors = [e for e in self.errors
                           if not e["path"].startswith(prefix)]
            for r in removed:
                self.reported.discard((r["url"], r["type"]))
            return len(removed)

    def is_suppressed(self, path):
        with self.lock:
            for p in self.suppressed:
                if path.startswith(p):
                    return True
            return False

    def add_result(self, rec):
        """记录一个命中结果。返回 False 表示已输出过，跳过。"""
        with self.lock:
            key = (rec["url"], rec["type"])
            if key in self.reported:
                return False
            self.reported.add(key)
            self.results.append(rec)
            return True

    def add_ignored(self, task, url, code, size, location=None, reason=""):
        """记录一条被视为 404 而忽略的路径（最终报告的 Ignored Paths）。"""
        with self.lock:
            self.ignored.append({
                "path": task.path,
                "url": url,
                "type": task.type,
                "from": task.from_,
                "remark": task.remark,
                "code": code,
                "size": size,
                "location": location,
                "reason": reason,
            })

    def add_error(self, task, url, reason):
        with self.lock:
            self.errors.append({
                "path": task.path,
                "url": url,
                "type": task.type,
                "from": task.from_,
                "remark": task.remark,
                "trytimes": task.trytimes,
                "reason": reason,
            })

    # ------------------------------------------------------------------
    # 速度统计
    # ------------------------------------------------------------------
    def record_request(self):
        """记一次请求，用于算速度。用 1 秒一格的滑动窗口，够用且便宜。"""
        now = int(time.time())
        with self.stat_lock:
            gap = now - self.req_last_sec
            if gap > 0:
                if gap >= SPEED_WINDOW:
                    self.req_buckets = [0] * SPEED_WINDOW
                else:
                    # 把空过去的秒补成 0，保证窗口是连续的时间轴
                    for i in range(gap):
                        idx = (self.req_last_sec + i + 1) % SPEED_WINDOW
                        self.req_buckets[idx] = 0
                self.req_last_sec = now
            idx = now % SPEED_WINDOW
            self.req_buckets[idx] += 1
            self.req_total += 1

    def speed(self):
        """窗口内平均每秒请求数（窗口已空则为 0）。"""
        now = int(time.time())
        with self.stat_lock:
            if now - self.req_last_sec >= SPEED_WINDOW:
                return 0.0
            return sum(self.req_buckets) / float(SPEED_WINDOW)

    def speed_exact(self):
        """当前窗口内的请求总数，调试与测试用。"""
        with self.stat_lock:
            return sum(self.req_buckets)

    # ------------------------------------------------------------------
    # 线程健康度
    # ------------------------------------------------------------------
    def thread_register(self, tid):
        with self.lock:
            self.thread_alive_ids.add(tid)
            self.thread_fails.setdefault(tid, 0)

    def thread_unregister(self, tid):
        with self.lock:
            self.thread_alive_ids.discard(tid)
            self.thread_paused.discard(tid)

    def thread_fail(self, tid):
        """连续失败 +1，返回当前次数。"""
        with self.lock:
            n = self.thread_fails.get(tid, 0) + 1
            self.thread_fails[tid] = n
            return n

    def thread_success(self, tid):
        """请求成功：连续失败计数清零。"""
        with self.lock:
            if self.thread_fails.get(tid):
                self.thread_fails[tid] = 0

    def thread_fail_count(self, tid):
        with self.lock:
            return self.thread_fails.get(tid, 0)

    def thread_pause(self, tid):
        with self.lock:
            self.thread_paused.add(tid)

    def thread_resume(self, tid):
        with self.lock:
            self.thread_paused.discard(tid)

    def all_other_threads_idle(self, tid):
        """除自己以外的活线程是否都在惩罚暂停中。"""
        with self.lock:
            others = [t for t in self.thread_alive_ids
                      if t != tid and t not in self.thread_paused]
            return not others

    def all_other_threads_healthy(self, tid):
        """除自己以外的活线程是否都健康（连续失败为 0）。"""
        with self.lock:
            for t in self.thread_alive_ids:
                if t == tid:
                    continue
                if self.thread_fails.get(t, 0) != 0:
                    return False
            return True

    def waf_request_wait(self):
        """请求进入 WAF 拦截等待模式。"""
        with self.lock:
            self.waf_wait_requested = True

    def take_wait_request(self):
        with self.lock:
            if self.waf_wait_requested:
                self.waf_wait_requested = False
                return True
            return False

    # ------------------------------------------------------------------
    # WAF 自动检测
    # ------------------------------------------------------------------
    def waf_note_fail(self, name, now=None):
        """一个 name 连续失败达到阈值时登记观察。返回 True 表示已登记。"""
        if not name:
            return False
        now = now if now is not None else time.time()
        with self.lock:
            if name in self.waf_window or self.is_name_blocked(name):
                return False
            self.waf_window[name] = now
            return True

    def waf_collect_due(self, now=None):
        """收集观察窗口已到的项。

        窗口内只有它自己 -> 加入忽略列表（后续不再检测）；
        窗口内还有别的项 -> 只把当前项移除，说明是站点的普遍问题而非该名称
        触发了 WAF。

        返回 (blocked, dropped) 两个 name 列表。
        """
        now = now if now is not None else time.time()
        with self.lock:
            due = [n for n, t in self.waf_window.items()
                   if now - t >= WAF_WINDOW_SECONDS]
            blocked = []
            dropped = []
            for name in due:
                self.waf_window.pop(name, None)
                # 窗口里还有别的项 -> 不是这个名称的问题
                if self.waf_window:
                    dropped.append(name)
                else:
                    self.waf_ignored.append(name)
                    self.bypass_names.add(name)
                    blocked.append(name)
            return blocked, dropped

    def is_name_bypassed(self, name):
        """该 name 是否在忽略列表里（WAF 判定 / 用户 --br）。"""
        with self.lock:
            return name in self.bypass_names

    def snapshot(self):
        with self.lock:
            return {
                "done": self.done,
                "pending": self.pending,
                "active": self.active,
                "results": len(self.results),
                "ignored": len(self.ignored),
                "errors": len(self.errors),
                "threads_alive": self.threads_alive,
                "target_threads": self.target_threads,
                "elapsed": time.time() - self.start_time,
                "queued": self.queue.qsize(),
                "dead_dirs": len(self.dead_dirs),
            }
