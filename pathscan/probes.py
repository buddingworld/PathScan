# -*- coding: utf-8 -*-
"""探测机制：目录探测(dircheck)、后缀检测、备份文件检测。

三种探测的目的都是「提前知道服务器会不会说谎」：
* dircheck   —— 服务器是否对任意路径都返回 200（软 404 / 万能 200）
* 后缀检测   —— 该目录下某个后缀是否根本不解析（比如未装 PHP 时 .php 全 404）
* 备份文件   —— 常见备份名 + 域名派生名，这类文件命中率高且常被漏扫
"""

import itertools

from .models import PROBE_PREFIX, Task, join_path, rand_token

# ----------------------------------------------------------------------
# 备份文件名
# ----------------------------------------------------------------------
BACKUP_NAMES = [
    "db", "Db", "DB",
    "web", "Web", "WEB",
    "config", "Config", "CONFIG",
    "data", "Data", "DATA",
    "database", "Database", "DATABASE",
    "website", "Website", "WEBSITE",
    "webconfig", "www", "WWW",
    "old", "Old", "OLD", "new", "New", "NEW",
    "bin", "Bin", "BIN", "Root", "root", "ROOT",
]

# 备份文件常用后缀，命中率远高于全后缀枚举
BACKUP_SUFFIXES = [
    ".zip", ".rar", ".tar", ".tar.gz", ".tgz", ".gz", ".7z", ".bz2",
    ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tmp", ".temp",
    ".sql", ".sql.gz", ".dump", ".txt", ".log", ".xml", ".conf", ".ini",
    ".json", ".yml", ".yaml", ".env", ".tar.bz2", ".war", ".jar", ".zip.bak",
]

# 目录名本身 + 这些后缀，用于「目录已存在则试探它的打包备份」
# 例如 /admin/web/ 存在 -> 再探 /admin/web.tar.gz 、/admin/web.zip ...
# 与 BACKUP_SUFFIXES 分开：这份是短名单，只挑最常见的打包/备份格式。
DIR_BACKUP_SUFFIXES = [
    ".tar.gz", ".7z", ".zip", ".rar", ".gz", ".tar",
    ".bak", ".sql", ".txt",
]


def build_backup_names(hostname):
    """按规格给的思路生成备份名，并做去重优化。

    规格里的原始实现有三个问题，这里一并修掉：
    1. 边遍历边 append 到同一个 list，外层的 range(len(tl)) 会跟着变；
    2. 对「域名派生的组合」也套用 3 个连接符，容易和基础名表重复；
    3. 大小写变体（Old/old/OLD）已经在基础表里，重复生成没有意义。

    IP 目标特殊处理：规格的算法会从 127.0.0.1 生成 ``0-0-1`` / ``127-0-0``
    这类排列组合，命中率为零却要发上千个请求。IP 场景下只保留完整 IP 的几种
    写法（``127.0.0.1`` / ``127001`` / ``127_0_0_1`` / ``127-0-0-1``），
    不再做子集排列组合。
    """
    names = list(BACKUP_NAMES)
    seen = set(names)

    host = hostname.split("/")[0].split(":")[0]
    parts = [p for p in host.split(".") if p]
    if len(parts) == 1:
        return names

    if _is_ipv4(parts):
        # 只探完整 IP 的四种写法，不做子集排列组合
        derived = [host, "".join(parts), "_".join(parts), "-".join(parts)]
    else:
        derived = []
        for r in range(1, len(parts) + 1):
            for combo in itertools.combinations(parts, r):
                for join_char in ("_", ".", "-"):
                    derived.append(join_char.join(combo))

    for candidate in derived:
        if candidate and candidate not in seen:
            seen.add(candidate)
            names.append(candidate)
    return names


def _is_ipv4(parts):
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return False
    return True


def build_backup_tasks(args, hostname, parent, remark=""):
    """为某个目录生成备份文件任务，按 -(名称 × 后缀) 展开。"""
    tasks = []
    for name in build_backup_names(hostname):
        for suffix in BACKUP_SUFFIXES:
            tasks.append(Task(type="file", name=name + suffix, parent=parent,
                              from_="backup", remark=remark))
    return tasks


def backup_probe_group_id(parent):
    return ("backup", parent)


def dircheck_group_id(parent):
    return ("dircheck", parent)


def suffix_group_id(parent, suffix):
    return ("suffix", parent, suffix)


def make_backup_probe_tasks(parent, suffixes, remark=""):
    """备份文件检测的探针：每个备份后缀各探一次。

    随机名 + 具体后缀（``__probe__ab12cd34.zip``、``__probe__ab12cd34.rar``），
    用来逐个判断「该后缀的备份文件」是否被服务器放行。

    用具体后缀而不是随机后缀：某些站点只对特定扩展名放行（比如对 .zip 一律
    返回 200 的下载路由），用随机后缀要么撞不上、要么把结论张冠李戴。

    名字带 ``__probe__`` 前缀，engine 靠它把探针和真正的备份任务区分开
    ——两者 from 都是 "backup"。
    """
    stem = PROBE_PREFIX + rand_token(8)
    return [Task(type="file", name=stem + suffix, parent=parent,
                 from_="backup", remark=remark) for suffix in suffixes]


def backup_suffix_of(name, suffixes):
    """找出文件名匹配的备份后缀，取最长匹配。

    ``db.tar.gz`` 同时以 ``.gz`` 和 ``.tar.gz`` 结尾，必须优先认长的那个，
    否则过滤时会按错误的后缀归类。
    """
    best = None
    for suffix in suffixes:
        if name.endswith(suffix) and (best is None or len(suffix) > len(best)):
            best = suffix
    return best


def build_dir_backup_tasks(parent, dirname, remark="", waf=0):
    """目录确认存在后，把它自身的打包备份加进队列。

    如 ``admin/web/`` 存在 -> 追加 ``admin/web.tar.gz``、``admin/web.zip`` 等。

    ``parent`` 是该目录所在的父目录，``dirname`` 是它自己的名字。
    生成的任务是文件类型，``from`` 为 ``backup_suffix``。
    """
    tasks = []
    for suffix in DIR_BACKUP_SUFFIXES:
        tasks.append(Task(type="file", name=dirname + suffix, parent=parent,
                          from_="backup_suffix", remark=remark, waf=waf))
    return tasks


def dir_backup_group_id(parent, dirname):
    return ("dirbackup", join_path(parent, dirname))


# ----------------------------------------------------------------------
# 目录探测
# ----------------------------------------------------------------------
def make_dircheck_task(parent, remark=""):
    """生成一个「必定不存在」的目录任务，用于判断服务器是否软 404。

    用纯随机名（8 位小写字母数字），不带后缀 —— 目录本来就不该带后缀，
    带后缀反而可能被某些站点的「未知文件类型」规则特殊处理，结论失真。
    """
    name = rand_token(8)
    return Task(type="dir", name=name, parent=parent, from_="dircheck",
                remark=remark)


def make_suffix_probe_tasks(parent, suffixes, remark=""):
    """为每个后缀生成一个探测任务。"""
    tasks = []
    for suffix in suffixes:
        name = "%s%s" % (rand_token(8), suffix)
        tasks.append(Task(type="file", name=name, parent=parent,
                          from_="suffixcheck", remark=remark))
    return tasks


# ----------------------------------------------------------------------
# 任务展开
# ----------------------------------------------------------------------
def build_leaf_tasks(name, remark, waf, parent, from_, args, type_,
                     depth_lo=0, depth_hi=None):
    """把词表里的一个条目展开成实际要扫描的任务。

    文件条目会按 --file-pre / -s / --files 展开成多个 name。
    depth_lo/depth_hi 来自备注的 "r" 字段，限定该条目只在这些层级测试。
    """
    tasks = []
    if type_ == "dir":
        tasks.append(Task(type="dir", name=name, parent=parent, from_=from_,
                          remark=remark, waf=waf,
                          depth_lo=depth_lo, depth_hi=depth_hi))
        return tasks

    # 文件：先按前缀和后缀组合展开
    variants = []
    prefixes = args.file_prefixes or [""]
    suffixes = args.suffixes or [""]
    for pre in prefixes:
        for suf in suffixes:
            variants.append("%s%s%s" % (pre, name, suf))
    if not args.suffixes and not args.file_prefixes:
        variants = [name]

    for v in variants:
        tasks.append(Task(type="file", name=v, parent=parent, from_=from_,
                          remark=remark, waf=waf,
                          depth_lo=depth_lo, depth_hi=depth_hi))
    return tasks
