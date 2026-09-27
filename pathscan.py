#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""PathScan 入口。

用法::

    python pathscan.py -u http://target -d d.txt -f f.txt -s .php,.html

不带参数运行时打印完整参数说明与示例::

    python pathscan.py --help

扫描中按 Ctrl+C 暂停，暂停时可输入 rp / at / status / exec / go / pause / stop。
"""

import sys
import time

from pathscan import cli, control, engine, output, rules


def main(argv=None):
    output.setup_console()

    parser = cli.build_parser()
    args = cli.Args(parser.parse_args(argv))
    printer = output.Printer(quiet=args.quiet)

    # ---- 参数校验 ----
    errors = cli.validate(args, printer)
    if errors:
        for e in errors:
            printer.raw("! %s" % e)
        printer.raw("")
        printer.raw(cli.format_demos())
        return 2

    # ---- 读词表 ----
    try:
        dir_entries, bad1 = cli.load_wordlist(args.dir, "dir")
        file_entries, bad2 = cli.load_wordlist(args.file, "file")
        files_ext_entries = []
        if args.files:
            files_ext_entries, bad3 = cli.load_wordlist(args.files, "files")
        else:
            bad3 = []
    except IOError as exc:
        printer.raw("! %s" % exc)
        printer.raw("")
        printer.raw(cli.format_demos())
        return 2

    for bad in (bad1, bad2, bad3):
        for lineno, text in bad:
            printer.info("备注不是合法 JSON（第 %d 行），按纯文本保留: %s"
                         % (lineno, text), tag="!")

    # ---- 规则 ----
    try:
        ignore_rules = rules.IgnoreRules(args.ir_pairs)
        bypass_rules = rules.BypassRules(args.br_pairs)
    except rules.RuleError as exc:
        printer.raw("! %s" % exc)
        return 2
    case_filter = rules.CaseFilter(args.cs)

    cli.banner(args, {
        "dirs": len(dir_entries),
        "files": len(file_entries),
        "files_ext": len(files_ext_entries),
    }, printer)

    # ---- 共享状态 ----
    from pathscan.models import GlobalState
    state = GlobalState(args)

    ctl = control.Controller(args, state, printer)
    control.install(args, state, printer, ctl)

    total_expected = (len(dir_entries) + len(file_entries) +
                      len(files_ext_entries) + len(args.ed_list) +
                      len(args.ef_list))

    eng = engine.build(args, state, printer, ignore_rules, bypass_rules,
                       case_filter, dir_entries, file_entries,
                       files_ext_entries)
    ctl.engine = eng
    ctl.namespace["engine"] = eng

    eng.start()

    interrupted = False
    try:
        finished = control.pause_loop(ctl, eng)
    except KeyboardInterrupt:
        # 极端情况下（比如暂停 REPL 里再按 Ctrl+C）兜底
        interrupted = True
        finished = False
        state.stop_flag = True
        with state.lock:
            state.cond.notify_all()
            state.pause_event.set()

    # ---- 收尾 ----
    state.pause_event.set()
    with state.lock:
        state.cond.notify_all()
    for w in eng.workers:
        w.join(timeout=3.0)

    printer.finish_live()
    snap = state.snapshot()
    printer.raw("")
    printer.raw("* 扫描结束%s，已完成 %d，耗时 %.1fs"
                % ("（被终止）" if not finished else "", snap["done"],
                   snap["elapsed"]))
    printer.raw("")
    output.print_report(state, args, printer)

    if args.of:
        ok, err = output.write_output(args.of, state, args)
        if ok:
            printer.info("结果已写入 %s" % args.of)
        else:
            printer.raw("! 写文件失败: %s" % err)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
