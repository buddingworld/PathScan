# -*- coding: utf-8 -*-
"""过滤规则：--ir 忽略规则、--br 路径排除、--cs 大小写。

--ir 的语义是「把匹配到的响应判定为 404」——既不记录结果，也不继续递归。
多条规则之间是或的关系，任意一条命中即生效。
"""

import re

IR_ATTRS = ("code", "size", "grep", "text", "location")
BR_ATTRS = ("name", "path", "url")


class RuleError(ValueError):
    pass


def _parse_int_or_range(value):
    """支持 ``404`` 与 ``100-200`` 两种写法。"""
    value = value.strip()
    if "-" in value[1:]:
        lo, hi = value.split("-", 1)
        return int(lo), int(hi)
    n = int(value)
    return n, n


class IgnoreRules(object):
    """--ir 规则集合。"""

    def __init__(self, pairs):
        self.rules = []
        for attr, value in pairs:
            if attr not in IR_ATTRS:
                raise RuleError(
                    "--ir 的属性必须是 %s 之一，收到 %r" % ("/".join(IR_ATTRS), attr))
            rule = {"attr": attr, "raw": value}
            if attr in ("code", "size"):
                try:
                    rule["lo"], rule["hi"] = _parse_int_or_range(value)
                except ValueError:
                    raise RuleError("--ir %s 需要整数或区间，收到 %r" % (attr, value))
            else:
                try:
                    rule["re"] = re.compile(value)
                except re.error as exc:
                    raise RuleError("--ir %s 正则无效: %s" % (attr, exc))
            self.rules.append(rule)

    def __len__(self):
        return len(self.rules)

    @staticmethod
    def _size_of(resp):
        """规格：优先 content-length，没有则用 len(body)。"""
        try:
            cl = resp.headers.get("Content-Length")
        except Exception:
            cl = None
        if cl is not None:
            try:
                return int(cl)
            except (TypeError, ValueError):
                pass
        try:
            return len(resp.content)
        except Exception:
            return None

    def matched(self, resp, code, size):
        """返回命中的规则（用于日志），没命中返回 None。"""
        if not self.rules:
            return None
        loc = None
        text = None
        for rule in self.rules:
            attr = rule["attr"]
            if attr == "code":
                if code is not None and rule["lo"] <= code <= rule["hi"]:
                    return rule
            elif attr == "size":
                if size is not None and rule["lo"] <= size <= rule["hi"]:
                    return rule
            else:
                if text is None:
                    try:
                        text = resp.text or ""
                    except Exception:
                        text = ""
                if attr == "grep":
                    if rule["re"].search(text):
                        return rule
                elif attr == "text":
                    if rule["raw"] in text:
                        return rule
                elif attr == "location":
                    if loc is None:
                        try:
                            loc = resp.headers.get("Location", "") or ""
                        except Exception:
                            loc = ""
                    if rule["raw"] in loc:
                        return rule
        return None


class BypassRules(object):
    """--br 规则：路径命中则不加入队列。"""

    def __init__(self, pairs):
        self.rules = []
        for attr, value in pairs:
            if attr not in BR_ATTRS:
                attr = "name"
            if value == "":
                raise RuleError("--br 的值不能为空")
            self.rules.append((attr, value))

    def __len__(self):
        return len(self.rules)

    def blocked(self, name, path, url):
        for attr, value in self.rules:
            if attr == "name":
                if value in name:
                    return True
            elif attr == "path":
                if value in path:
                    return True
            elif attr == "url":
                if value in url:
                    return True
        return False


class CaseFilter(object):
    """--cs 大小写敏感过滤。

    --cs 1（默认）时 ``Admin`` 与 ``admin`` 是两个不同路径，都要扫。
    --cs 0 时已经扫过 ``Admin`` 就不再扫 ``admin``。
    去重集合放在 GlobalState 里（claim_url），这里只负责提供归一化后的键。
    """

    def __init__(self, case_sensitive=True):
        self.case_sensitive = bool(case_sensitive)

    def normalize(self, name):
        return name if self.case_sensitive else name.lower()
