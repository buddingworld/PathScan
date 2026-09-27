# -*- coding: utf-8 -*-
"""探测机制：目录探测(dircheck)、后缀检测、备份文件检测。

三种探测的目的都是「提前知道服务器会不会说谎」：
* dircheck   —— 服务器是否对任意路径都返回 200（软 404 / 万能 200）
* 后缀检测   —— 该目录下某个后缀是否根本不解析（比如未装 PHP 时 .php 全 404）
* 备份文件   —— 常见备份名 + 域名派生名，这类文件命中率高且常被漏扫
"""

import itertools

from .models import Task, join_path, rand_token

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


PROBE_PREFIX = "__probe__"


def make_backup_probe_task(parent, remark=""):
    """备份文件检测的探针：随机名 + 随机备份后缀。

    名字带 __probe__ 前缀，engine 靠它把这个任务和真正的备份文件任务区分开
    ——两者 from 都是 "backup"。
    """
    name = "%s%s.%s" % (PROBE_PREFIX, rand_token(8), rand_token(4))
    return Task(type="file", name=name, parent=parent, from_="backup",
                remark=remark)


# ----------------------------------------------------------------------
# 目录探测
# ----------------------------------------------------------------------
def make_dircheck_task(parent, remark=""):
    """生成一个「必定不存在」的目录任务，用于判断服务器是否软 404。

    随机名 + 随机后缀双随机：只随机名字的话，某些服务器会对「无后缀路径」
    统一返回 200，探测结论就废了。
    """
    name = "%s.%s" % (rand_token(8), rand_token(5))
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
