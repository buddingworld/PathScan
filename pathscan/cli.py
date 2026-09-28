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

_CS_HELP = "--cs1 ~ --cs9: 自定义字符集 ?1~?9，各自独立，可嵌套 ?l?d。如 --cs1 ?l?d"

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
参数说明与示例
==================================================================
-u  目标 url。不带 scheme 时自动补 http://
       -u http://target.com        -u 192.168.1.1:8080

-t  -r  线程数与递归层数。层数按 parent 里的 / 数量计算
       -t 20 -r 3

-m  请求方法。目录扫描用 head 最快，被拦时换 get
       -m head        -m get

-d  -f  目录/文件词表，两行格式相同，二者都必需
       名称[#备注]，备注是 JSON
       d.txt:  admin
               backup#{"waf":3}
       -d d.txt -f f.txt

--files  带后缀的文件词表（无需再配 -s）
       --files f_ext.txt

-s  文件后缀，逗号分隔。同时用于后缀探测：后缀不可信时该目录跳过它
       -s .php,.aspx,.jsp

--file-pre  给文件名加前缀，与 -s 组合展开
       --file-pre "old_,new_" -s .php     -> old_x.php new_x.php ...

--ed --ef  额外目录/文件，支持掩码
       --ed "admin_new,admin2"           直接列名字
       --ed "admin?d"                    admin0..admin9
       --ed "{C-2:dev,test}"             devtest（组合，顺序无关）
       --ed "{P-2:dev,test}"             devtest testdev（排列）
       --ed "{dev,test,prd}"             三选一
       --ed "?u?l" --cs1 "0123456789"    自定义字符集

--csc  组合扩展的连接字符，空串总是隐含包含
       --ed "{C-2:dev,test}" --csc ",_,-"
              -> devtest dev_test dev-test

--rh  请求头，可多次
       --rh "Cookie: a=b" --rh "X-Forwarded-For: 127.0.0.1"

--mode  1=目录补尾斜杠(admin/)  2=目录不补(admin)  默认 2
       --mode 1

--cs  大小写敏感。开时 Admin 与 admin 都扫；关时只扫其中一个
       --cs 1        --cs 0

--ti  线程内请求间隔，可用区间表示随机
       --ti 0.5      --ti 1-3

--ir  把匹配的响应判定为 404。可多次，属性：%s
       --ir size 1234            固定长度
       --ir code 500-599         状态码区间
       --ir grep "not found"     响应体正则
       --ir text "Error"         响应体文本
       --ir location /login      跳转目标

--br  路径命中则不入队。可多次，属性：%s
       --br name logout          名称含 logout
       --br path /static/        路径含 /static/

--proxy  代理
       --proxy http://127.0.0.1:8081
       --proxy socks5h://127.0.0.1:1080

--ka  keep-alive 复用次数
       --ka 0        无限复用
       --ka 200      复用 200 次后重连（默认）
       --ka -1       不复用，每个请求新建连接

--rt  --timeout  失败重试次数与单次超时
       --rt 3 --timeout 5

--of  结果导出路径（文本，含 Ignored Paths 与 Result）
       --of out.txt

--cq  安静模式，不输出实时日志
       --cq

完整的用法示例
       python pathscan.py -u http://target.com -d d.txt -f f.txt \\
              -s .php,.html -t 20 -r 3 --ed "admin?d"
==================================================================
%s
==================================================================
扫描中按 Ctrl+C 暂停，可用指令: rp / at / status / exec / go / pause / stop
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
        description="PathScan %s - 递归型 Web 目录/文件扫描器" % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    p.add_argument("-u", "--url", required=True, metavar="URL",
                   help="目标 url")
    p.add_argument("-t", "--thread", type=int, default=3, metavar="N",
                   help="扫描线程数 (默认 3)")
    p.add_argument("-m", "--method", default="head", metavar="M",
                   choices=METHODS,
                   help="请求方法: %s (默认 head)" % "|".join(METHODS))
    p.add_argument("-r", "--recursion", type=int, default=5, metavar="N",
                   help="递归最大层数 (默认 5)")

    g = p.add_argument_group("词表")
    g.add_argument("-d", "--dir", required=True, metavar="FILE",
                   help="目录词表，每行 name[#json备注]")
    g.add_argument("-f", "--file", required=True, metavar="FILE",
                   help="文件名词表，不含后缀，每行 name[#json备注]")
    g.add_argument("--files", metavar="FILE",
                   help="带后缀的文件词表")
    g.add_argument("-s", "--suffix", metavar="LIST",
                   help="文件后缀，逗号分隔，如 .php,.aspx。同时用于后缀探测")
    g.add_argument("--file-pre", dest="file_pre", metavar="LIST",
                   help="文件前缀，逗号分隔，如 old_,new_")

    g = p.add_argument_group("掩码扩展")
    g.add_argument("--ed", metavar="MASK",
                   help="额外目录，支持 hashcat 掩码与 {C-2:}/{P-2:} 扩展")
    g.add_argument("--ef", metavar="MASK", help="额外文件，语法同 --ed")
    g.add_argument("--csc", "--custom-charset-connect", dest="csc",
                   metavar="LIST",
                   help="组合扩展的连接字符，逗号分隔，如 \",_,-\"")
    # --cs1 ~ --cs9 是 9 个各自独立的字符集，但帮助里只占一行：
    # 只有 --cs1 显示说明，其余用 SUPPRESS 隐藏，避免参数列表被撑散。
    for i in CS_INDICES:
        g.add_argument("--cs%d" % i, dest="cs%d" % i, metavar="SET",
                       help=(_CS_HELP if i == 1 else argparse.SUPPRESS))

    g = p.add_argument_group("请求")
    g.add_argument("--rh", "--request-headers", dest="rh", action="append",
                   metavar="H", help='请求头，可多次，如 --rh "Cookie: a=b"')
    g.add_argument("--proxy", metavar="URL",
                   help="代理，支持 http/https/socks5/socks5h")
    g.add_argument("--ka", "--keep-alive", dest="ka", type=int, default=200,
                   metavar="N",
                   help="keep-alive 复用次数: 0=无限，N=复用N次后重连，"
                        "负数=不复用 (默认 200)")
    g.add_argument("--rt", "--retry-times", dest="rt", type=int, default=3,
                   metavar="N", help="请求最大失败重试次数 (默认 3)")
    g.add_argument("--timeout", type=float, default=10.0, metavar="SEC",
                   help="单次请求超时秒数 (默认 10)")
    g.add_argument("--ti", "--thread-interval", dest="ti", default="0",
                   metavar="T",
                   help="线程内请求间隔，如 1 / 0.2 / 1-3 (默认 0)")
    g.add_argument("--mode", type=int, default=2, choices=(1, 2), metavar="1|2",
                   help="1=目录补 /，2=目录不补 / (默认 2)")
    g.add_argument("--cs", "--case-sensitive", dest="cs", type=int, default=1,
                   choices=(0, 1), metavar="0|1",
                   help="大小写敏感，1=开 0=关 (默认 1)")
    g.add_argument("--bh", "--bypass-headers", dest="bh", metavar="V",
                   help="bypass headers 测试 (待开发)")

    g = p.add_argument_group("规则")
    g.add_argument("--ir", "--ignore-rules", dest="ir", nargs=2,
                   action="append", metavar=("ATTR", "VALUE"),
                   help="忽略规则，可多次。ATTR: %s" % _IR_ATTRS)
    g.add_argument("--br", "--bypass-rules", dest="br", nargs=2,
                   action="append", metavar=("ATTR", "VALUE"),
                   help="排除路径规则，可多次。ATTR: %s" % _BR_ATTRS)

    g = p.add_argument_group("输出")
    g.add_argument("--of", "--output-file", dest="of", metavar="FILE",
                   help="结果导出路径")
    g.add_argument("--od", "--ok-dirs", dest="od", action="append",
                   metavar="PATH",
                   help="已确认存在的目录，形如 dir1/dir2/dir3/。每一层都会"
                        "被直接判定为存在（不经过探测），并与其他目录一起"
                        "参与递归。可多次")
    g.add_argument("--cq", "--quiet", dest="quiet", action="store_true",
                   help="安静模式：不输出实时日志，只保留最终报告")
    g.add_argument("--debug", dest="debug", action="store_true",
                   help="输出诊断信息（探测结算、--od 登记、延迟组放行等）")

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
    raise ValueError("参数需要 2 个值: %r" % (pair,))


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
            self.ed_list = maskmod.expand_specs(self.ed, self.custom_charsets,
                                                self.connectors)
            self.ef_list = maskmod.expand_specs(self.ef, self.custom_charsets,
                                                self.connectors)
        except maskmod.MaskError as exc:
            self.mask_error = str(exc)

    def _parse_connectors(self):
        if self.csc is None:
            return []
        # 空串是隐含的，这里只保留显式给出的连接符
        return [c for c in maskmod.split_top_level(self.csc) if c != ""]


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
            raise ValueError('--rh 格式应为 "Name: value"，收到 %r' % raw)
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
        raise ValueError("层级不能为负: %r" % raw)
    if hi is not None and hi < lo:
        raise ValueError("层级区间非法: %r" % raw)
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
        raise IOError("词表文件不存在: %s" % path)
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
        errors.append("线程数必须 >= 1")
    if args.recursion < 1:
        errors.append("递归层数必须 >= 1")
    if args.rt < 0:
        errors.append("重试次数不能为负")
    if args.method.lower() not in METHODS:
        errors.append("请求方法 %r 不支持，可选: %s"
                      % (args.method, "/".join(METHODS)))
    if not os.path.isfile(args.dir):
        errors.append("目录词表不存在: %s" % args.dir)
    if not os.path.isfile(args.file):
        errors.append("文件词表不存在: %s" % args.file)
    if args.files and not os.path.isfile(args.files):
        errors.append("带后缀文件词表不存在: %s" % args.files)
    if args.of:
        outdir = os.path.dirname(os.path.abspath(args.of))
        if not os.path.isdir(outdir):
            errors.append("输出目录不存在: %s" % outdir)
    if args.proxy:
        scheme = args.proxy.split("://", 1)[0].lower()
        if scheme not in ("http", "https", "socks5", "socks5h", "socks4",
                          "socks4a"):
            errors.append("代理协议 %r 不支持" % scheme)
        elif scheme.startswith("socks"):
            try:
                import socks  # noqa: F401
            except ImportError:
                errors.append("使用 socks 代理需要安装 PySocks: pip install PySocks")
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
    lines.append(" 目标 : %s" % args.url)
    lines.append(" 后缀 : %s" % (", ".join(args.suffixes) or "(无)"))
    lines.append(" 词表 : 目录 %d / 文件 %d / 带后缀文件 %d"
                 % (sizes["dirs"], sizes["files"], sizes["files_ext"]))
    lines.append("=" * 66)
    for line in lines:
        safe_print(line)
