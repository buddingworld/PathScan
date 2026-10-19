# -*- coding: utf-8 -*-
"""命令行参数定义与校验。

参数数量多，这里集中处理，engine / probes 只从 Args 对象读值，不再碰 argparse。
"""

import argparse
import os
import re
import sys

from . import mask as maskmod

VERSION = "1.0.0"

METHODS = ("get", "post", "head", "put", "delete", "options", "patch", "trace")
FROM_VALUES = ("common", "suffixcheck", "dircheck", "backup",
               "backup_suffix")

# 自定义字符集的编号范围：--cs1 ~ --cs9
CS_INDICES = range(1, 10)

_IR_ATTRS = "code | size | grep | text | location"
_BR_ATTRS = "name | path | url"

_CS_HELP = ("--cs1 ~ --cs9: custom charsets ?1~?9, independent, can nest "
            "?l?d. e.g. --cs1 ?l?d")

# 常见场景的现成命令，参数缺失/出错时和 --help 都会打印
DEMOS = [
    ("Common IIS", "pathscan.py -d d.txt -f f.txt -s .aspx --cs 0"),
    ("Common JSP", "pathscan.py -d d.txt -f f.txt -s .jsp --cs 1"),
    ("Common PHP", "pathscan.py -d d.txt -f f.txt -s .php --cs 1"),
    ("Full   IIS", "pathscan.py -d d.txt -f f.txt -s .aspx,.ashx,.asmx --cs 0 "
                   "--ed ?1?1?1?1,pinyinpinyin.txt --cs1 ?h?H"),
    ("Full   JSP", "pathscan.py -d d.txt -f f.txt -s .jsp --cs 0 "
                   "--ed ?1?1?1?1,pinyinpinyin.txt --cs1 ?h"),
]


def format_demos():
    """把 DEMOS 排成对齐的一段文本。"""
    width = max(len(label) for label, _ in DEMOS)
    lines = ["Common Commands:"]
    for label, cmd in DEMOS:
        lines.append("  %s: %s" % (label.ljust(width), cmd))
    return "\n".join(lines)

_EPILOG = """
Options and examples
==================================================================
-u  target url. http:// is added when the scheme is missing
       -u http://target.com        -u 192.168.1.1:8080

-t  -r  threads and recursion depth. Depth counts / in parent
       -t 20 -r 3

-m  request method. head is fastest for directory scanning; switch to get
    when it gets blocked
       -m head        -m get

-d  -f  directory / file wordlists, same line format, both required
       name[#remark], remark is JSON
       d.txt:  admin
               backup#{"waf":3}
       -d d.txt -f f.txt

--files  file wordlist that already carries suffixes (no -s needed)
       --files f_ext.txt

-s  file suffixes, comma separated. Also probed per directory, together with
    the --files suffixes and the backup suffixes: once a suffix is proven
    untrustworthy (catch-all 200, WAF 403) the whole directory skips it
       -s .php,.aspx,.jsp

--file-pre  prefix file names, expanded together with -s
       --file-pre "old_,new_" -s .php     -> old_x.php new_x.php ...

--ed --ef  extra directories / files, mask syntax supported
       --ed "admin_new,admin2"           plain names
       --ed "admin?d"                    admin0..admin9
       --ed "{C-2:dev,test}"             devtest (combination, order free)
       --ed "{P-2:dev,test}"             devtest testdev (permutation)
       --ed "{dev,test,prd}"             pick one of three
       --ed "?u?l" --cs1 "0123456789"    custom charset

--csc  connector characters for combinations; the empty string is implicit
       --ed "{C-2:dev,test}" --csc ",_,-"
              -> devtest dev_test dev-test

--rh  request headers, repeatable
       --rh "Cookie: a=b" --rh "X-Forwarded-For: 127.0.0.1"

--mode  1=directories get a trailing slash (admin/)  2=no slash (admin),
       default 2
       --mode 1

--cs  case sensitivity. On: both Admin and admin are scanned; off: only one
       --cs 1        --cs 0

--ti  per-thread delay between requests, a range means random
       --ti 0.5      --ti 1-3

--ir  treat matching responses as 404, exactly like a real 404: no result,
       no recursion, not in the final report - only a live log line.
       Repeatable, attributes: %s
       --ir size 1234            exact length
       --ir code 500-599         status code range
       --ir grep "not found"     body regex
       --ir text "Error"         body text
       --ir location /login      redirect target

--br  paths matching are never queued. Repeatable, attributes: %s
       --br name logout          name contains logout
       --br path /static/        path contains /static/

--nb  no automatic backup paths (backup files, directory self backups)
       --nb
       Note: directories marked with waf in the wordlist always skip their
       self backups - the name carries the same sensitive string.

--od  directories known to exist, registered level by level
       --od dir1/dir2/dir3/
       Each level gets one dircheck: a fake 404 level does not expand its
       wordlist children, but the chain continues (a fake dir1 does not
       stop dir2 or dir3). Every path segment also joins --ed, so dir1 /
       dir2 / dir3 are tested at the root as ordinary directories.

--proxy  proxy
       --proxy http://127.0.0.1:8081
       --proxy socks5h://127.0.0.1:1080

--ka  keep-alive reuse count
       --ka 0        reuse forever
       --ka 200      reconnect after 200 reuses (default)
       --ka -1       no reuse, new connection per request

--rt  --timeout  retry limit and per-request timeout
       --rt 3 --timeout 5

--of  export path (text, contains Ignored Paths and Result)
       --of out.txt

--cq  quiet mode, no live log
       --cq

Full example
       python pathscan.py -u http://target.com -d d.txt -f f.txt \\
              -s .php,.html -t 20 -r 3 --ed "admin?d"
==================================================================
%s
==================================================================
Ctrl+C pauses the scan; commands: rp / at / status / exec / go / pause / stop
""" % (_IR_ATTRS, _BR_ATTRS, format_demos())


def _parse_cs_numbers(ns):
    """从 --cs1~--cs9 收集自定义字符集，返回 {"1": "?l?d", ...}。"""
    out = {}
    for i in CS_INDICES:
        val = getattr(ns, "cs%d" % i, None)
        if val:
            out[str(i)] = val
    return out


class DemoArgumentParser(argparse.ArgumentParser):
    """参数出错时补打常用命令示例。

    argparse 默认只打印 usage + 错误原因，光看那句很难凑出正确命令；
    这里在报错后追加现成的示例。
    """

    def error(self, message):
        # 先把实时日志的临时行收尾，免得提示接在日志后面
        try:
            from .output import safe_print
            safe_print("")
        except Exception:
            pass
        self.print_usage(sys.stderr)
        self.exit(2, "%s: error: %s\n\n%s\n"
                  % (self.prog, message, format_demos()))


def build_parser():
    p = DemoArgumentParser(
        prog="pathscan",
        description="PathScan %s - recursive web directory/file scanner" % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    p.add_argument("-u", "--url", required=True, metavar="URL",
                   help="target url")
    p.add_argument("-t", "--thread", type=int, default=3, metavar="N",
                   help="worker threads (default 3)")
    p.add_argument("-m", "--method", default="head", metavar="M",
                   choices=METHODS,
                   help="request method: %s (default head)" % "|".join(METHODS))
    p.add_argument("-r", "--recursion", type=int, default=5, metavar="N",
                   help="max recursion depth (default 5)")

    g = p.add_argument_group("wordlists")
    g.add_argument("-d", "--dir", required=True, metavar="FILE",
                   help="directory wordlist, one name[#json remark] per line")
    g.add_argument("-f", "--file", required=True, metavar="FILE",
                   help="file name wordlist, no suffixes, name[#json remark]")
    g.add_argument("--files", metavar="FILE",
                   help="file wordlist that already carries suffixes")
    g.add_argument("-s", "--suffix", metavar="LIST",
                   help="file suffixes, comma separated, e.g. .php,.aspx. "
                        "Also probed per directory (together with the "
                        "--files suffixes and the backup suffixes)")
    g.add_argument("--file-pre", dest="file_pre", metavar="LIST",
                   help="file name prefixes, comma separated, e.g. old_,new_")

    g = p.add_argument_group("mask expansion")
    g.add_argument("--ed", metavar="MASK",
                   help="extra directories, hashcat masks and {C-2:}/{P-2:} "
                        "supported")
    g.add_argument("--ef", metavar="MASK", help="extra files, same syntax")
    g.add_argument("--csc", "--custom-charset-connect", dest="csc",
                   metavar="LIST",
                   help="connector characters for combinations, e.g. \",_,-\"")
    # --cs1 ~ --cs9 是 9 个各自独立的字符集，但帮助里只占一行：
    # 只有 --cs1 显示说明，其余用 SUPPRESS 隐藏，避免参数列表被撑散。
    for i in CS_INDICES:
        g.add_argument("--cs%d" % i, dest="cs%d" % i, metavar="SET",
                       help=(_CS_HELP if i == 1 else argparse.SUPPRESS))

    g = p.add_argument_group("request")
    g.add_argument("--rh", "--request-headers", dest="rh", action="append",
                   metavar="H", help='request header, repeatable, '
                                     'e.g. --rh "Cookie: a=b"')
    g.add_argument("--proxy", metavar="URL",
                   help="proxy, http/https/socks5/socks5h supported")
    g.add_argument("--ka", "--keep-alive", dest="ka", type=int, default=200,
                   metavar="N",
                   help="keep-alive reuse count: 0=unlimited, N=reconnect "
                        "after N reuses, negative=no reuse (default 200)")
    g.add_argument("--rt", "--retry-times", dest="rt", type=int, default=3,
                   metavar="N", help="max retries per request (default 3)")
    g.add_argument("--timeout", type=float, default=10.0, metavar="SEC",
                   help="per-request timeout in seconds (default 10)")
    g.add_argument("--ti", "--thread-interval", dest="ti", default="0",
                   metavar="T",
                   help="per-thread delay, e.g. 1 / 0.2 / 1-3 (default 0)")
    g.add_argument("--mode", type=int, default=2, choices=(1, 2), metavar="1|2",
                   help="1=directories get a trailing /, 2=no / (default 2)")
    g.add_argument("--cs", "--case-sensitive", dest="cs", type=int, default=1,
                   choices=(0, 1), metavar="0|1",
                   help="case sensitivity, 1=on 0=off (default 1)")
    g.add_argument("--bh", "--bypass-headers", dest="bh", metavar="V",
                   help="bypass headers test (not implemented)")

    g = p.add_argument_group("rules")
    g.add_argument("--ir", "--ignore-rules", dest="ir", nargs=2,
                   action="append", metavar=("ATTR", "VALUE"),
                   help="ignore rules, repeatable. ATTR: %s" % _IR_ATTRS)
    g.add_argument("--br", "--bypass-rules", dest="br", nargs=2,
                   action="append", metavar=("ATTR", "VALUE"),
                   help="path exclusion rules, repeatable. ATTR: %s" % _BR_ATTRS)
    g.add_argument("--nb", "--no-bak", dest="nb", action="store_true",
                   help="no automatic backup paths: no backup files "
                        "(name x suffix), no directory self backups. Names "
                        "written in the wordlist are still scanned")

    g = p.add_argument_group("output")
    g.add_argument("--of", "--output-file", dest="of", metavar="FILE",
                   help="export results to a file")
    g.add_argument("--od", "--ok-dirs", dest="od", action="append",
                   metavar="PATH",
                   help="directories known to exist, e.g. dir1/dir2/dir3/. "
                        "Each level is registered and recursed; each level "
                        "gets one dircheck, and a fake 404 level does not "
                        "expand its wordlist children (the chain continues). "
                        "Each path segment is also added to --ed, so dir1 / "
                        "dir2 / dir3 are tested at the root too. Repeatable")
    g.add_argument("--cq", "--quiet", dest="quiet", action="store_true",
                   help="quiet mode: no live log, only the final report")
    g.add_argument("--debug", dest="debug", action="store_true",
                   help="diagnostics (probe settlement, --od registration, "
                        "delayed group release, ...)")

    p.add_argument("--version", action="version",
                   version="PathScan %s" % VERSION)
    return p


def _normalize_pair(pair, which):
    """--ir / --br 是 nargs=2 的 action=append，正常用法是 2 个独立参数。

    但用户常把值写成 ``"--br name keep out"`` 这种带空格的形式，argparse 会
    把它当成「3 个 token」而报错。这里在 argv 阶段就把多出来的 token 合并回
    第二个值。此处只做兜底：已经是 2 元组时直接返回。
    """
    if len(pair) >= 2:
        return (pair[0], pair[1])
    raise ValueError("expected 2 values, got %r" % (pair,))


class Args(object):
    """解析后的参数容器。"""

    def __init__(self, ns):
        self.__dict__.update(vars(ns))
        self.url = normalize_url(self.url)
        self.headers = parse_headers(self.rh)
        self.custom_charsets = _parse_cs_numbers(ns)
        self.connectors = self._parse_connectors()
        self.suffixes = parse_suffixes(self.suffix)
        self.file_prefixes = parse_list(self.file_pre)
        self.ti_range = parse_interval(self.ti)
        self.ir_pairs = []
        for pair in (self.ir or []):
            self.ir_pairs.append(_normalize_pair(pair, "ir"))
        self.br_pairs = []
        for pair in (self.br or []):
            self.br_pairs.append(_normalize_pair(pair, "br"))
        self.ka = self.ka
        self.keep_alive = self.ka >= 0
        self.ka_limit = 0 if self.ka == 0 else self.ka
        # --od：逐层展开的「已确认存在」目录
        self.ok_dirs = parse_ok_dirs(self.od)
        # --ed / --ef 的掩码在这里就展开，保证 Args 构造完即可用；
        # 出错时留给 validate() 统一汇报，不在这里抛。
        self.mask_error = None
        self.ed_list = []
        self.ef_list = []
        try:
            self.ed_list = _clean_names(maskmod.expand_specs(
                self.ed, self.custom_charsets, self.connectors))
            self.ef_list = _clean_names(maskmod.expand_specs(
                self.ef, self.custom_charsets, self.connectors))
        except maskmod.MaskError as exc:
            self.mask_error = str(exc)
        # --od 的每一段名字也按 --ed 追加：--od dir1/dir2/dir3 时，dir1、
        # dir2、dir3 各自也会在根目录下当普通目录测一次（探测 + 递归）。
        for path in self.ok_dirs:
            for seg in path.split("/"):
                if seg and seg not in self.ed_list:
                    self.ed_list.append(seg)

    def _parse_connectors(self):
        if self.csc is None:
            return []
        # 空串是隐含的，这里只保留显式给出的连接符
        return [c for c in maskmod.split_top_level(self.csc) if c != ""]


def _clean_names(names):
    """去掉名字两端的斜杠，并丢弃清空后的项。

    掩码展开会原样保留用户写法，``--ed "admin/"`` 得到的就是 ``admin/``；
    带着尾斜杠进队列，目录命中后加后缀会拼出 ``admin/.zip`` 这种空文件名
    路径。归一化放在入口，后面所有生成器都不必再防。
    """
    out = []
    for name in names:
        name = str(name).strip("/")
        if name:
            out.append(name)
    return out


def parse_ok_dirs(values):
    """解析 --od：``dir1/dir2/dir3/`` -> 逐层的所有前缀。

    返回按深度由浅到深、去重后的路径列表：

        ["dir1", "dir1/dir2", "dir1/dir2/dir3"]

    这样每一层都会被视为已确认存在的目录，既能直接登记为结果，
    也能作为递归的起点（避免因为中间某一层没在词表里而断链）。

    支持多次传入，单次内也支持逗号分隔（与 -s / --ed 等参数一致）。
    """
    out = []
    seen = set()
    specs = []
    for raw in values or []:
        if raw is None:
            continue
        # 逗号分隔，但路径里正常不会出现逗号
        specs.extend(p for p in str(raw).split(",") if p.strip())
    for spec in specs:
        # 允许 dir1/dir2/dir3/ 也允许 dir1/dir2/dir3
        text = spec.strip().strip("/")
        if not text:
            continue
        parts = [p for p in text.split("/") if p]
        for i in range(1, len(parts) + 1):
            path = "/".join(parts[:i])
            if path not in seen:
                seen.add(path)
                out.append(path)
    return out


def normalize_url(url):
    """补上 scheme，并去掉末尾的 /。"""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url.rstrip("/")


def parse_headers(items):
    """--rh "Cookie: a=b" -> {"Cookie": "a=b"}"""
    headers = {}
    for raw in items or []:
        if ":" not in raw:
            raise ValueError('--rh expects "Name: value", got %r' % raw)
        name, value = raw.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def parse_suffixes(raw):
    """后缀列表，统一补前导点。"""
    out = []
    for item in parse_list(raw):
        if not item.startswith("."):
            item = "." + item
        out.append(item)
    return out


def parse_list(raw):
    if raw is None:
        return []
    return [x.strip() for x in raw.split(",") if x.strip() != ""]


def parse_interval(raw):
    """--ti 解析：``1`` / ``0.2`` / ``1-3``。返回 (lo, hi)。"""
    if raw is None:
        return (0.0, 0.0)
    raw = str(raw).strip()
    if "-" in raw[1:]:
        lo, hi = raw.split("-", 1)
        return (float(lo), float(hi))
    val = float(raw)
    return (val, val)


def parse_depth_range(raw):
    """解析备注里的 ``r`` 字段：``"0-1"`` / ``"2"`` / ``"1-"``。

    表示该条目只在指定层级的目录中测试。层数按 parent 里的 / 数量 + 1 计算
    （根目录下的条目是第 1 层）。

    返回 (lo, hi)，hi 为 None 表示不设上限。无此字段时返回 (0, None)。
    """
    if raw is None or raw == "":
        return (0, None)
    text = str(raw).strip()
    if "-" in text[1:]:
        lo_s, hi_s = text.split("-", 1)
        lo = int(lo_s) if lo_s.strip() else 0
        hi = int(hi_s) if hi_s.strip() else None
    else:
        lo = hi = int(text)
    if lo < 0:
        raise ValueError("depth must not be negative: %r" % raw)
    if hi is not None and hi < lo:
        raise ValueError("invalid depth range: %r" % raw)
    return (lo, hi)


def load_wordlist(path, kind):
    """读取词表文件。

    每行 ``name#备注``，备注是 JSON。识别三个字段：

    * ``waf``    —— 该名称易被 WAF 拦截的阈值（默认 0 = 不检测）
    * ``r``      —— 仅在这些层级测试，如 ``"0-1"``、``"2"``、``"1-"``
    * ``remark`` —— 备注文本。仅在该路径**请求结果非 404**（未被规则视为 404）
                   时，追加显示在实时日志与最终输出的行尾

    返回 (entries, bad_lines)，entry 为 dict:
        {"name","remark","waf","depth_lo","depth_hi"}
    """
    entries = []
    bad = []
    if not path:
        return entries, bad
    if not os.path.isfile(path):
        raise IOError("wordlist not found: %s" % path)
    import json
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            name = line
            remark = ""
            waf = 0
            depth_lo, depth_hi = 0, None
            if "#" in line:
                name, remark_raw = line.split("#", 1)
                name = name.strip()
                remark_raw = remark_raw.strip()
                if remark_raw.startswith("{"):
                    try:
                        obj = json.loads(remark_raw)
                    except ValueError:
                        bad.append((lineno, remark_raw))
                        obj = None
                    if isinstance(obj, dict):
                        try:
                            waf = int(obj.get("waf", 0) or 0)
                        except (TypeError, ValueError):
                            waf = 0
                        # remark：原样保留，是否显示由「请求是否非 404」决定，
                        # 与 remark 的值本身无关
                        remark = obj.get("remark", "")
                        remark = "" if remark is None else str(remark)
                        if "r" in obj:
                            try:
                                depth_lo, depth_hi = parse_depth_range(obj["r"])
                            except ValueError as exc:
                                bad.append((lineno, str(exc)))
                    elif obj is not None:
                        # JSON 不是对象：当纯文本备注用
                        remark = remark_raw
                else:
                    remark = remark_raw
            # 两端的斜杠去掉：条目写成 ``admin/`` 时，加后缀会拼出
            # ``admin/.zip`` 这种空文件名路径，压根不该发出去
            name = name.strip("/")
            if not name:
                continue
            entries.append({
                "name": name, "remark": remark, "waf": waf,
                "depth_lo": depth_lo, "depth_hi": depth_hi,
            })
    return entries, bad


def validate(args, printer=None):
    """语义校验，出错返回错误信息列表。"""
    errors = []
    if args.thread < 1:
        errors.append("thread count must be >= 1")
    if args.recursion < 1:
        errors.append("recursion depth must be >= 1")
    if args.rt < 0:
        errors.append("retry count must not be negative")
    if args.method.lower() not in METHODS:
        errors.append("unsupported method %r, pick one of: %s"
                      % (args.method, "/".join(METHODS)))
    if not os.path.isfile(args.dir):
        errors.append("directory wordlist not found: %s" % args.dir)
    if not os.path.isfile(args.file):
        errors.append("file wordlist not found: %s" % args.file)
    if args.files and not os.path.isfile(args.files):
        errors.append("file wordlist not found: %s" % args.files)
    if args.of:
        outdir = os.path.dirname(os.path.abspath(args.of))
        if not os.path.isdir(outdir):
            errors.append("output directory not found: %s" % outdir)
    if args.proxy:
        scheme = args.proxy.split("://", 1)[0].lower()
        if scheme not in ("http", "https", "socks5", "socks5h", "socks4",
                          "socks4a"):
            errors.append("unsupported proxy scheme %r" % scheme)
        elif scheme.startswith("socks"):
            try:
                import socks  # noqa: F401
            except ImportError:
                errors.append("socks proxy requires PySocks: "
                              "pip install PySocks")
    if getattr(args, "mask_error", None):
        errors.append(args.mask_error)
    return errors


def banner(args, sizes, printer):
    """启动横幅。按需求只显示目标、后缀、词表三项。"""
    from .output import safe_print
    lines = []
    lines.append("=" * 66)
    lines.append(" PathScan %s" % VERSION)
    lines.append("=" * 66)
    lines.append(" target : %s" % args.url)
    lines.append(" suffix : %s" % (", ".join(args.suffixes) or "(none)"))
    lines.append(" words  : dir %d / file %d / file-with-suffix %d"
                 % (sizes["dirs"], sizes["files"], sizes["files_ext"]))
    lines.append("=" * 66)
    for line in lines:
        safe_print(line)
