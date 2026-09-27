# PathScan

递归型 Web 目录/文件扫描器。多线程、连接复用、带探测机制，用于在目录/文件数量
较大的场景下快速枚举 Web 路径。

## 快速开始

```bash
python pathscan.py -u http://target.com -d d.txt -f f.txt
```

`-d` 与 `-f` 都是必需参数（按规格要求）。最小可用命令：

```bash
python pathscan.py -u http://target.com -d d.txt -f f.txt -s .php,.html
```

## 完整参数说明

```bash
python pathscan.py --help
```

`--help` 里除了分组列出的参数表，还有逐参数说明与示例（掩码写法、规则写法等）。
参数缺失或出错时也会附带常用命令示例：

```
Common Commands:
  Common IIS: pathscan.py -d d.txt -f f.txt -s .aspx --cs 0
  Common JSP: pathscan.py -d d.txt -f f.txt -s .jsp --cs 1
  Common PHP: pathscan.py -d d.txt -f f.txt -s .php --cs 1
  Full   IIS: pathscan.py -d d.txt -f f.txt -s .aspx,.ashx,.asmx --cs 0 --ed ?1?1?1?1,pinyinpinyin.txt --cs1 ?h?H
  Full   JSP: pathscan.py -d d.txt -f f.txt -s .jsp --cs 0 --ed ?1?1?1?1,pinyinpinyin.txt --cs1 ?h
```

## 实时日志与最终报告

扫描中每完成一次请求打一条实时日志：

```
ThreadID:0  ->    /admin [ok]
ThreadID:1  ->    /nope1 [err]
```

路径不足 40 字符时补空格对齐，超过 40 字符原样输出（此时不对齐）。
尾部附加 `Speed: {n}/s`（10 秒窗口内请求数 ÷ 10，为估算值，开销可忽略）。

备注非空时会追加在行尾（见下方词表格式的 `remark` 字段）。
`[ok ]` 与 `[err]` 等长，便于对齐。

`[err]`（404、被 `--ir` 判为 404、网络失败）只是「路过」，会被后续请求原地覆盖；
`[ok]`（命中）会固定下来，之后的日志另起新行。重定向到文件或管道时自动关闭覆盖，
且只保留 `[ok]` 行，避免日志被 404 刷爆；`--cq` 可完全关闭实时日志。

**实时日志只输出到屏幕，不会写进 `--of` 的文件**——导出文件里只有汇总报告。

扫描结束后输出汇总报告（同时写入 `--of`）：

```
http://target/
Ignored Paths:
    /login  [200] (99)
Result(OK):
    /admin  [200] (10)
    /api    [301] (0) -> /api/v2
```

`(size)` 优先取 `Content-Length`，没有则取 `len(response.content)`。

## 扫描中暂停

按 `Ctrl+C` 暂停，暂停后进入指令提示符（`pathscan> `）。暂停提示会另起新行，
不会和实时日志挤在同一行：

| 指令 | 说明 |
|---|---|
| `rp <前缀>` | 移除已扫描出结果的路径，前缀匹配。`rp admin_x` 会清掉 `admin_*` |
| `at <n>` | 增加 n 个线程；n 为负数表示减少 |
| `status` | 显示当前进度、速率、线程数 |
| `exec <代码>` | 临时执行代码，如 `exec test_list.add(123)` |
| `go` | 继续扫描 |
| `pause` | 保持暂停 |
| `stop` | 终止扫描 |
| `help` | 显示帮助 |

暂停中再按一次 `Ctrl+C` 直接退出。

## 词表格式

一行一个条目，`名称#备注`，备注是 JSON：

```
admin
backup#{"waf":3}
rootonly#{"r":"0-1"}
tagged#{"remark":"ZhiyuanOA"}
```

| 字段 | 说明 |
|---|---|
| `waf` | 该名称易被 WAF 拦截的阈值。同一名称的失败次数超过该值后全局不再扫描。默认 `0` = 不检测 |
| `r` | **仅在这些层级测试**。`"0-1"` 表示 0~1 层，`"2"` 表示只测第 2 层，`"1-"` 表示 1 层及以上。层数按目录算：`/test` 是 1 层，`/xx/test` 是 2 层 |
| `remark` | 备注文本。**仅在该路径请求结果非 404**（含未被规则视为 404）时，追加显示在实时日志与最终输出行尾。与备注的值无关 |

`r` 字段的例子：

```
test#{"r":"0-1"}      # /test 会测，/admin/test 不会
deep#{"r":"2-"}       # 只在第 2 层及更深测
mix#{"remark":"后台","waf":3,"r":"0-2"}
```

`remark` 的显示例子：

```
admin#{"remark":"后台管理"}   # 返回 200 -> 显示
Ignored Paths: 里的条目不显示    # 被判为 404 的路径
```

实时日志：

```
ThreadID:1  ->  /admin    [ok ]  Speed: 0.9/s  #后台管理
```

## 探测机制

扫描开始时、以及每进入一个新目录时，会先发三类探测，根据结论决定后续扫什么。
**常规任务与备份任务会暂存在队列外，等探测出结论后再放行**，避免探测还没回来就
把上千个任务扫掉。

| 探测 | 做法 | 结论 |
|---|---|---|
| 目录探测 | 请求 `{随机8位}.{随机后缀}` | 若返回存在，说明服务器对任意路径都返回 200（软 404），该目录下所有路径按 404 处理；**根目录命中则终止扫描** |
| 后缀检测 | 对 `-s` 的每个后缀请求 `{随机8位}{后缀}` | 若返回存在，该后缀结果不可信，整个目录不再扫该后缀 |
| 备份检测 | 请求 `{随机8位}.{随机备份后缀}` | 若返回存在，服务器对备份类路径有特殊放行，跳过该目录的备份检测 |

备份名由基础名表 + 域名派生名组成。域名会按 `_` / `.` / `-` 连接符做子集组合
（`abc.google.com` → `abc`、`google`、`abc.google` 等，共 48 个）；**IP 目标不做
排列组合**，只保留完整 IP 的四种写法（`127.0.0.1` / `127001` / `127_0_0_1` /
`127-0-0-1`，共 37 个），因为 `0-0-1` 这类子集组合命中率为零。

后缀检测会沿上级目录复用结论：同一站点后缀可用性几乎不随目录变化，
祖先目录已探明的后缀不再重复探测。

## WAF 自动检测与线程自保

三个机制都会自动生效，不需要额外参数。

### 名称级 WAF 检测

某个路径的**失败次数**（网络层失败，不含 404）累计超过 2 次时，把它的 `{name}`
放进计数器观察 **5 秒**。窗口结束时统计：

* 计数器里**只有它自己** → 判定该名称触发了 WAF，加入忽略列表，后续不再检测；
* 计数器里**还有别的名称** → 只把当前项移除（是站点的普遍问题，不是这个名称）。

### 线程级自保

每个线程维护一个连续失败计数器：请求成功清零，失败 +1。
累计超过 **5** 次时该线程惩罚性暂停 **30 秒**。30 秒后：

* 其他线程**也都在暂停** → 视为 IP 被整体封禁，转入 WAF 拦截等待模式；
* 其他线程**都正常**（失败计数为 0）→ 该线程继续跑。

### WAF 拦截等待模式

表现与按 `Ctrl+C` 暂停相同（暂停扫描、可敲指令），但会检测按键：

* **有按键** → 进入指令模式，由你决定 `go` / `stop`；
* **30 分钟内无任何按键** → 视为无人值守，自动 `go` 恢复扫描。

`status` 指令会显示实时速度、连续失败中的线程、以及被 WAF 忽略的名称。

## 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-u` | 必填 | 目标 url |
| `-t` | 3 | 线程数 |
| `-m` | head | 请求方法 `get\|post\|head\|...` |
| `-r` | 5 | 递归最大层数 |
| `-d` | 必填 | 目录词表文件 |
| `-f` | 必填 | 文件名词表文件（不含后缀） |
| `--files` | — | 带后缀的文件词表 |
| `-s` | — | 文件后缀，逗号分隔，如 `.php,.aspx`。同时驱动后缀探测 |
| `--file-pre` | — | 文件前缀，逗号分隔，如 `old_,new_` |
| `--ed` | — | 额外目录，支持掩码 |
| `--ef` | — | 额外文件，支持掩码 |
| `--cs1`..`--cs9` | — | 自定义字符集 `?1`~`?9`，各自独立，可嵌套 `?l?d` |
| `--csc` | — | 组合扩展的连接字符，如 `",_,-"` |
| `--rh` | — | 请求头，可多次，如 `--rh "Cookie: a=b"` |
| `--mode` | 2 | 1=目录补 `/`，2=不补 |
| `--cs` | 1 | 大小写敏感开关 |
| `--ti` | 0 | 线程内请求间隔，如 `1`、`0.2`、`1-3`（区间随机） |
| `--of` | — | 结果导出路径 |
| `--ir` | — | 忽略规则，2 参数可多次：`--ir <属性> <值>` |
| `--br` | — | 排除路径规则，2 参数可多次：`--br <属性> <值>` |
| `--proxy` | — | 代理，支持 `http/https/socks5/socks5h` |
| `--ka` | 200 | 复用次数：`0`=无限，`N`=复用 N 次后重连，负数=不复用 |
| `--rt` | 3 | 请求最大失败重试次数 |
| `--timeout` | 10 | 单次请求超时秒数 |
| `--bh` | — | bypass headers 测试，**待开发**，当前解析后忽略 |
| `--cq` | — | 安静模式，只输出结果 |

### `--ir` 属性

把匹配到的响应判定为 404（不记录结果，也不继续递归）：

- `code` 状态码，支持区间 `404` / `100-200`
- `size` 响应长度，优先 `Content-Length`，没有则取 `len(body)`
- `grep` 响应体正则匹配
- `text` 响应体文本匹配
- `location` 301/302 跳转的目标 url

```bash
# 把长度恰好 1234 的响应当作 404
python pathscan.py -u http://t -d d.txt -f f.txt --ir size 1234
```

### `--br` 属性

路径命中则不入队：`name`（默认）、`path`、`url`。

```bash
# 路径里含 logout 的一律不扫
python pathscan.py -u http://t -d d.txt -f f.txt --br name logout
```

## 掩码

`--ed` / `--ef` 支持 hashcat 风格掩码与组合扩展：

```bash
# admin1 admin2 admin3, devtest / dev_test / dev-test
python pathscan.py -u http://t -d d.txt -f f.txt \
  --ed 'admin?d,{C-2:dev,test}' --csc ',_-'
```

| 语法 | 含义 |
|---|---|
| `?l ?u ?d ?s ?a ?b ?h ?H` | hashcat 标准字符集 |
| `?1`..`?9` | 自定义字符集，由 `--cs1`..`--cs9` 定义，可嵌套 |
| `{C-2:dev,test,prd}` | 取 2 个做**组合**（顺序无关） |
| `{P-2:dev,test,prd}` | 取 2 个做**排列**（顺序有关） |
| `{dev,test,prd}` | 任取一个 |

`--csc` 指定连接字符；空串总是隐含包含，所以 `--csc ',_'` 会同时产出
`devtest` 和 `dev_test`。

## 架构

```
pathscan.py          入口：参数解析 + 启动 + 收尾导出
pathscan/
  cli.py             全部参数定义、校验、词表读取
  mask.py            hashcat 掩码 + {C-n}/{P-n} 组合扩展
  models.py          Task（对应规格的 JSON）、GlobalState、TaskQueue
  probes.py          dircheck / 后缀检测 / 备份文件生成
  scanner.py         每线程一个 Session，连接池与 --ka 复用控制
  engine.py          队列、线程池、递归展开、探测结算
  control.py         Ctrl+C 暂停 + 指令 REPL
  output.py          结果渲染与 --of 导出（cp936 安全的输出层）
  rules.py           --ir / --br / --cs
```

### 队列任务格式

任务与规格里的 JSON 一一对应，可无损往返：

```json
{"type":"dir","trytimes":0,"name":"admin","parent":"",
 "from":"dircheck","remark":"","waf":3}
```

`from` 取值：`common`（常规）、`suffixcheck`（后缀检测）、`dircheck`（目录检测）、
`backup`（备份检测）、`exec`（暂停时 exec 指令塞入）。

### 关键实现说明

- **结束判定**用待完成计数而不是「队列为空」。探测任务还在飞行时队列可能是空的，
  只看队列会提前退出。
- **探测结算在锁内完成**：先把放行的任务计入待完成数，再从暂存区摘掉，
  避免其他线程在中间窗口误判扫描结束。
- **探测任务失败也会结算**。网络不通时不能硬推断服务器行为——那会静默漏掉
  整个目录的结果，所以失败时保守放行。
- **重试由调度器控制**（`max_retries=0`），requests 内部不重试，避免两套重试叠加
  把 `--rt` 的语义放大。
- **输出层对 cp936 控制台做了防护**，打印非 ASCII 路径不会崩。

## 测试

```bash
python -m pathscan.mask          # 掩码引擎自测
python tests/test_pathscan.py    # 端到端扫描测试（内嵌靶机）
python tests/test_cli.py         # CLI 集成 + 暂停指令测试
python tests/test_waf.py         # WAF 检测 / 线程自保 / 速度统计
python tests/target_server.py 8000 [normal|soft404|nohost]   # 手动靶机
```

`tests/target_server.py` 的三种模式分别模拟正常站点、软 404 站点、
以及不处理特定后缀的站点，方便手动验证探测行为。
