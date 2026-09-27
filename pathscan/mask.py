# -*- coding: utf-8 -*-
"""hashcat 风格掩码引擎，并扩展 {C-n:...} / {P-n:...} / {a,b,c} 三种组合语法。

支持的语法
----------
* 基础字符集： ``?l ?u ?d ?s ?a ?b ?h ?H``
* 自定义字符集： ``?1`` ~ ``?9``，由 ``-1`` ~ ``-9`` 定义，定义里可以再嵌套
  ``?l`` / ``?d`` 或直接写字符，例如 ``-1 ?l?d``、``-1 abc?d``
* 组合扩展：
    - ``{C-2:dev,test,prd,web}``  取 2 个做组合（顺序无关）
    - ``{P-2:dev,test,prd,web}``  取 2 个做排列（顺序有关）
    - ``{dev,test,prd}``          任取其中一个
* ``--csc`` 指定组合结果的连接字符，空串总是隐含包含。

掩码可以出现在 ``--ed`` / ``--ef`` 里，展开在启动时一次性完成。
"""

import itertools
import re

# hashcat 标准字符集
BUILTIN = {
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "d": "0123456789",
    "h": "0123456789abcdef",
    "H": "0123456789ABCDEF",
    "s": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}
BUILTIN["a"] = BUILTIN["l"] + BUILTIN["u"] + BUILTIN["d"] + BUILTIN["s"]
BUILTIN["b"] = "".join(chr(i) for i in range(256))

# 掩码展开的安全上限，防止 ?a?a?a?a?a?a 之类把内存跑爆
DEFAULT_LIMIT = 1000000

_GROUP_RE = re.compile(r"^([CP])-(\d+):(.*)$", re.S)


class MaskError(ValueError):
    """掩码语法错误。"""


def split_top_level(s, sep=","):
    """按 sep 切分，但忽略花括号内部的 sep。

    ``{dev,test}`` 里的逗号属于组合语法，不能被当成 --ed 的分隔符切开。
    ``--csc ",_,-"`` 期望切出空串，所以空段要保留。
    """
    out = []
    buf = []
    depth = 0
    for ch in s:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        if ch == sep and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    out.append("".join(buf))
    return out


def _dedupe(s):
    seen = set()
    out = []
    for ch in s:
        if ch not in seen:
            seen.add(ch)
            out.append(ch)
    return "".join(out)


def resolve_charset(spec, custom, _guard=None):
    """把字符集定义展开成实际字符集合，支持内部嵌套 ?l / ?1 之类。"""
    if _guard is None:
        _guard = set()
    out = []
    i = 0
    n = len(spec)
    while i < n:
        ch = spec[i]
        if ch == "?" and i + 1 < n:
            key = spec[i + 1]
            if key in BUILTIN:
                out.append(BUILTIN[key])
                i += 2
                continue
            if key.isdigit() and key != "0":
                if key not in custom:
                    raise MaskError("字符集 ?%s 未定义（需要 -%s）" % (key, key))
                if key in _guard:
                    raise MaskError("字符集 ?%s 循环引用" % key)
                out.append(resolve_charset(custom[key], custom, _guard | {key}))
                i += 2
                continue
            out.append("?")
            i += 1
            continue
        out.append(ch)
        i += 1
    return _dedupe("".join(out))


def _apply_connectors(items, connectors):
    """用连接字符把一组元素拼成字符串。空串总是隐含包含。"""
    conns = [""] + [c for c in connectors if c != ""]
    out = []
    for group in items:
        for c in conns:
            out.append(c.join(group))
    return out


def _expand_group(body, connectors):
    """展开一个 {...} 组合。返回该位置所有可能的字符串。"""
    m = _GROUP_RE.match(body)
    if m:
        kind, size, items_s = m.group(1), int(m.group(2)), m.group(3)
        items = split_top_level(items_s)
        items = [x for x in items if x != ""]
        if size <= 0:
            raise MaskError("组合数量必须为正: {%s}" % body)
        if not items:
            raise MaskError("组合内容为空: {%s}" % body)
        if kind == "C":
            combos = itertools.combinations(items, size)
        else:
            combos = itertools.permutations(items, size)
        return _dedupe_list(_apply_connectors(list(combos), connectors))

    # {dev,test,prd} —— 任取一个，不用连接符
    items = [x for x in split_top_level(body) if x != ""]
    if not items:
        raise MaskError("组合内容为空: {%s}" % body)
    return _dedupe_list(items)


def _dedupe_list(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _tokenize(pattern, custom, connectors):
    """把掩码切成若干「同位候选列表」，之后做笛卡尔积。"""
    tokens = []
    lit = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "?" and i + 1 < n:
            if lit:
                tokens.append(["".join(lit)])
                lit = []
            key = pattern[i + 1]
            if key in BUILTIN:
                tokens.append(list(BUILTIN[key]))
                i += 2
                continue
            if key.isdigit() and key != "0":
                if key not in custom:
                    raise MaskError("字符集 ?%s 未定义（需要 -%s）" % (key, key))
                tokens.append(list(resolve_charset(custom[key], custom, {key})))
                i += 2
                continue
            lit.append("?")
            i += 1
            continue
        if ch == "{":
            end = pattern.find("}", i + 1)
            if end < 0:
                raise MaskError("花括号未闭合: %s" % pattern)
            if lit:
                tokens.append(["".join(lit)])
                lit = []
            tokens.append(_expand_group(pattern[i + 1:end], connectors))
            i = end + 1
            continue
        lit.append(ch)
        i += 1
    if lit:
        tokens.append(["".join(lit)])
    return tokens


def count_expansion(pattern, custom, connectors):
    """估算展开规模，用于提前拦截爆炸式掩码。"""
    total = 1
    for tok in _tokenize(pattern, custom, connectors):
        total *= len(tok)
    return total


def expand_mask(pattern, custom=None, connectors=None, limit=DEFAULT_LIMIT):
    """展开单个掩码为字符串列表。"""
    custom = custom or {}
    connectors = connectors or []
    tokens = _tokenize(pattern, custom, connectors)
    if not tokens:
        return [""]
    total = 1
    for tok in tokens:
        total *= len(tok)
        if total > limit:
            raise MaskError(
                "掩码 %s 展开超过 %d 条，请收紧范围" % (pattern, limit))
    out = []
    for combo in itertools.product(*tokens):
        out.append("".join(combo))
    return out


def expand_specs(raw, custom=None, connectors=None, limit=DEFAULT_LIMIT):
    """展开命令行传入的整个规格串（如 ``--ed admin_new,{C-2:dev,test}``）。

    先用 split_top_level 按逗号切开——花括号内部的逗号属于组合语法，不会被
    误切——再逐个掩码展开，最后去重并保持顺序。
    """
    if raw is None:
        return []
    specs = split_top_level(raw) if isinstance(raw, str) else list(raw)
    result = []
    for spec in specs:
        spec = spec.strip()
        if not spec:
            continue
        result.extend(expand_mask(spec, custom, connectors, limit))
    return _dedupe_list(result)


# ----------------------------------------------------------------------
# 自测：python -m pathscan.mask
# ----------------------------------------------------------------------
def _selftest():
    assert expand_mask("a?d") == ["a0", "a1", "a2", "a3", "a4",
                                  "a5", "a6", "a7", "a8", "a9"]

    # 自定义字符集，含嵌套
    assert resolve_charset("?l?d", {}) == resolve_charset("?l", {}) + \
        resolve_charset("?d", {})
    assert expand_mask("?1", {"1": "ab"}) == ["a", "b"]
    assert expand_mask("?1", {"1": "?d"})[:3] == ["0", "1", "2"]
    assert expand_mask("x?1", {"1": "abc"}) == ["xa", "xb", "xc"]

    # 排列 P-2：顺序有关，dev/test 两种顺序都出现
    got = expand_mask("{P-2:dev,test}")
    assert sorted(got) == ["devtest", "testdev"], got
    got = expand_mask("{P-2:dev,test,prd}")
    assert len(got) == 6, got

    # 组合 C-2：顺序无关，只产出 ("dev","test") 一组，再套连接符
    got = expand_mask("{C-2:dev,test}")
    assert sorted(got) == ["devtest"], got
    got = expand_mask("{C-2:dev,test}", connectors=["_"])
    assert sorted(got) == ["dev_test", "devtest"], got

    # 连接符含空串：三个连接符产出三条
    got = expand_mask("{C-2:dev,test}", connectors=["_", "-"])
    assert sorted(got) == sorted(["devtest", "dev-test", "dev_test"]), got

    # C-2 取 2 个以上时组合数正确：C(4,2)=6
    got = expand_mask("{C-2:dev,test,prd,web}")
    assert len(got) == 6, got

    # 单选
    assert sorted(expand_mask("{dev,test,prd}")) == ["dev", "prd", "test"]

    # 与字面量混合
    assert sorted(expand_mask("admin_{dev,test}")) == ["admin_dev", "admin_test"]

    # top-level 切分不破坏花括号
    assert split_top_level("{dev,test},admin2") == ["{dev,test}", "admin2"]
    assert split_top_level(",_,-") == ["", "_", "-"]

    # 组合扩展 + 多掩码（split_top_level 保证 '{dev,test},admin2' 不被切坏）
    got = expand_specs("admin_new,admin2,{C-2:dev,test}", connectors=["_"])
    assert "admin_new" in got and "admin2" in got, got
    assert "dev_test" in got and "devtest" in got, got
    got = expand_specs("{dev,test},admin2")
    assert sorted(got) == ["admin2", "dev", "test"], got
    assert expand_specs(None) == []

    # 上限保护
    try:
        expand_mask("?a?a?a?a", limit=10)
        raise AssertionError("应该触发上限保护")
    except MaskError:
        pass

    # 未定义字符集
    try:
        expand_mask("?5")
        raise AssertionError("应该报未定义")
    except MaskError:
        pass

    # 循环引用
    try:
        expand_mask("?1", {"1": "?1"})
        raise AssertionError("应该报循环引用")
    except MaskError:
        pass

    print("mask.py selftest OK")


if __name__ == "__main__":
    _selftest()
