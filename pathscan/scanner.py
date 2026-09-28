# -*- coding: utf-8 -*-
"""请求执行层：每个线程一个 Session，负责连接池、keep-alive、代理、超时。

重试策略
--------
``--rt`` 的语义是「任务级重试」——请求失败就把 trytimes+1 重新压回队列，
而不是在 requests 内部重试。所以这里 ``max_retries=0``，把重试完全交给
engine 控制，避免两套重试叠加导致次数被放大。
"""

import random
import time
import warnings

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util import parse_url as _parse_url
except Exception:                                    # pragma: no cover
    _parse_url = None

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# 这些状态码表示「路径不存在」，不算错误，也不计入 WAF
NOT_FOUND_CODES = (404, 410, 400, 501)


class LimitedHTTPAdapter(HTTPAdapter):
    """在 HTTPAdapter 上加一个「复用 N 次后重连」的开关。

    requests 本身不暴露 keep-alive 复用次数，这里按 host 统计取连接的次数，
    累计到上限就清掉连接池，逼下一次重新建 TCP 连接。
    """

    def __init__(self, reuse_limit=0, **kwargs):
        self._reuse_limit = reuse_limit
        self._counts = {}
        super(LimitedHTTPAdapter, self).__init__(**kwargs)

    def _host_key(self, url):
        if _parse_url is None:
            return url
        try:
            parsed = _parse_url(url)
            return "%s://%s:%s" % (parsed.scheme, parsed.host, parsed.port)
        except Exception:
            return url

    def get_connection(self, url, proxies=None):
        key = self._host_key(url)
        used = self._counts.get(key, 0)
        if self._reuse_limit and used >= self._reuse_limit:
            try:
                self.poolmanager.clear()
            except Exception:
                pass
            self._counts.clear()
            used = 0
        conn = super(LimitedHTTPAdapter, self).get_connection(url, proxies)
        self._counts[key] = used + 1
        return conn


class Resp(object):
    """一次请求的结果。``error`` 非 None 表示请求失败（网络层）。"""

    __slots__ = ("url", "code", "size", "location", "error", "elapsed",
                 "_resp")

    def __init__(self, url):
        self.url = url
        self.code = None
        self.size = None
        self.location = None
        self.error = None
        self.elapsed = 0.0
        self._resp = None

    @property
    def ok(self):
        return self.error is None

    @property
    def exists(self):
        """路径是否存在。请求失败或 404 类状态码都算不存在。"""
        if self.error is not None:
            return False
        return self.code not in NOT_FOUND_CODES

    def text(self):
        if self._resp is None:
            return ""
        try:
            return self._resp.text or ""
        except Exception:
            return ""

    def __repr__(self):
        if self.error:
            return "<Resp %s ERR %s>" % (self.url, self.error)
        return "<Resp %s %s size=%s>" % (self.url, self.code, self.size)


def build_url(base, path, type_, mode):
    """拼接请求 url。mode 1 时目录补尾斜杠，文件永不补。"""
    if not path:
        return base + "/"
    url = base + "/" + path
    if type_ == "dir" and mode == 1:
        url += "/"
    return url


class Scanner(object):
    """Session 工厂 + 单次请求执行。每个线程持有自己的 Scanner 实例。"""

    def __init__(self, args, thread_id=0):
        self.args = args
        self.thread_id = thread_id
        self.session = self._make_session()
        self._ti_lo, self._ti_hi = args.ti_range
        self.request_count = 0

    def _make_session(self):
        args = self.args
        s = requests.Session()

        # 不读环境/系统代理。requests 默认 trust_env=True，会去读
        # HTTP_PROXY / HTTPS_PROXY / ALL_PROXY 等环境变量，Windows 上还会读
        # 注册表里的系统代理设置——扫描目标通常在内网，被系统代理劫持会让
        # 请求全部失败或走到错误的出口。
        #
        # 注意只设 s.proxies = {} 是没用的：trust_env 为 True 时 requests 会把
        # 环境代理 setdefault 合并进本次请求，必须直接关掉这个开关。
        # 关掉后 .netrc 也不再被读取（避免悄悄套用本机凭据）。
        s.trust_env = False

        # 线程自己的连接池：pool_maxsize 至少要够本线程用
        limit = args.ka_limit if args.keep_alive else 0
        adapter = LimitedHTTPAdapter(
            reuse_limit=limit, pool_connections=args.thread,
            pool_maxsize=args.thread, max_retries=0)
        s.mount("http://", adapter)
        s.mount("https://", adapter)

        s.headers.update({
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/120.0 Safari/537.36"),
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        })
        if args.headers:
            s.headers.update(args.headers)
        if not args.keep_alive:
            s.headers["Connection"] = "close"

        # --proxy 显式指定的代理才生效
        if args.proxy:
            s.proxies = {"http": args.proxy, "https": args.proxy}
        else:
            # 双保险：即使将来有人改回 trust_env，这里也把代理清空
            s.proxies = {}

        s.verify = False
        return s

    def sleep_interval(self):
        """--ti 线程内间隔，区间则取随机。"""
        if self._ti_hi <= 0:
            return
        if self._ti_hi == self._ti_lo:
            time.sleep(self._ti_lo)
        else:
            time.sleep(random.uniform(self._ti_lo, self._ti_hi))

    def fetch(self, url, method=None):
        """发一次请求。不重试——重试由 engine 按 --rt 控制。"""
        args = self.args
        method = (method or args.method).upper()
        resp = Resp(url)
        started = time.time()
        try:
            if method in ("GET", "HEAD", "OPTIONS", "DELETE", "TRACE"):
                r = self.session.request(method, url, timeout=args.timeout,
                                         allow_redirects=False)
            else:
                # POST/PUT/PATCH：目录扫描通常不需要 body，发个空的
                r = self.session.request(method, url, timeout=args.timeout,
                                         allow_redirects=False, data=b"")
            resp._resp = r
            resp.code = r.status_code
            resp.location = r.headers.get("Location")
            resp.size = self._size_of(r)
        except Exception as exc:
            resp.error = "%s: %s" % (type(exc).__name__, exc)
        resp.elapsed = time.time() - started
        self.request_count += 1
        return resp

    @staticmethod
    def _size_of(r):
        """规格要求：优先 content-length，没有则取 len(response.body)。"""
        cl = r.headers.get("Content-Length")
        if cl is not None:
            try:
                return int(cl)
            except (TypeError, ValueError):
                pass
        try:
            return len(r.content)
        except Exception:
            return 0

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass
