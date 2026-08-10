# OpenLDAP 2.6.13 `lloadd` 固定源码分析

## 0. 分析边界与结论口径

> 实现状态（2026-08-04）：本文仍保留为当时的静态源码分析记录；其后已在
> `internal/lloadd` 和 `ldap-go lloadd` 中实现文档化子集，并增加固定源码契约、
> 本地并发/竞态测试以及 OpenLDAP 2.6.13 实时差分测试。当前兼容状态仍为
> `partial`，具体范围以 `docs/compatibility.md` 为准。

- 固定源码目录：`/tmp/openldap-2.6.13.IjWZV9`
- 固定 Git commit：`d172686d3d270bc961b78f3ff00d7019c8dfb094`
- 分析对象：该提交中的 `servers/lloadd`，并以同一提交中的 man page、管理员指南、官方 lloadd 测试，以及 `slapd/back-ldap`、`slapd/back-meta` 作对照。
- 方法：严格静态只读分析。未编译、未运行测试、未启动任何服务、未建立网络连接，也未修改 OpenLDAP 源码或 `ldap-go`。
- 本文中的“已实现”表示固定源码中存在可达实现路径；“文档称”仅表示文档表述；“疑似缺陷/待差分”表示源码内部存在不一致，必须由固定 oracle 实测确认，不能直接当成预期行为复刻。
- 行号均针对上述固定 commit。格式为 `文件:函数:起始行`，局部行为再给具体行号。

## 1. 总结

1. `lloadd` 不是目录服务器、LDAP 数据库或 `slapd` 的替代品。它是 LDAPv3 感知的、按 operation 进行复用的反向代理/负载均衡器。它不保存条目、schema、索引、ACL 或密码，因此不存在 OpenLDAP 数据文件兼容问题。
2. 普通请求的 protocolOp 和 controls 以原始 BER 片段转发，主要改写 LDAP messageID；普通响应同样保留 response/control 内容并恢复客户端 messageID。它不会解释 DN、filter、attribute、entry 或 referral 的业务语义。
3. 默认每个 operation 可选不同 backend/upstream。`Bind` 多步交换、`write_coherence`、`restrict_exop`、`restrict_control` 可把客户端固定到 backend 或具体 upstream。
4. upstream 分成 regular pool 与 bind pool。regular 连接可并发复用，通常先用 `bindconf` 服务身份绑定；bind 连接专用于客户端 Bind，在一个 Bind 期间独占。
5. 没有“等待 upstream 空闲”的 operation 队列。达到 client/backend/connection 上限或连接暂时忙时，当前 operation 立即得到 `LDAP_BUSY`；没有已建立的合适连接时得到 `LDAP_UNAVAILABLE`。
6. 没有独立 LDAP ping/health-search。健康度由 DNS、TCP connect、TLS/StartTLS、服务 Bind、实际收发成功以及 socket keepalive 间接决定；失败后按固定间隔重建池，无指数退避或 jitter。
7. 客户端 StartTLS 在 lloadd 本地终止，和 upstream TLS 配置相互独立。客户端 SASL 代理有明确限制；SASL EXTERNAL 在本地根据客户端证书 DN 完成，其他多步 SASL Bind 固定到 bind upstream。
8. LDAP Cancel extended operation没有 messageID 内层改写实现，官方示例明确建议配置为 `reject`。Abandon 则有正确的 client/upstream messageID 映射。Transactions 没有事务状态机，只能通过 `connection` restriction 保证同一 upstream，固定范围会延续到下一次 Bind。
9. `cn=config` 和 `cn=monitor` 仅在 lloadd 作为 slapd 模块时可用；该模块仍拥有独立 listener，且没有任何 slapd `bi_op_*` 回调，流量与 slapd 普通数据库完全隔离。
10. 源码存在若干必须由 oracle 固化的边界或疑似缺陷：文档默认值与代码不同、`idletimeout`/legacy `restrict` 只解析不执行、`isolate` 标为 TODO、Bind 后 affinity 状态清理可疑、在线变更 `bindconf` 后 PRIVILEGED 判定疑似反向、daemon 的 gentle shutdown 不像真正 drain、DNS 仅尝试首个 addrinfo。

因此，Go 重写是可行的，但目标应定义为“固定 commit 的 lloadd wire/状态行为兼容”，而不是“完整 OpenLDAP 服务端兼容”。在没有完成后文差分矩阵前，不能声称完全兼容。

## 2. 代码组织与核心对象

| 文件 | 主要职责 | 关键锚点 |
|---|---|---|
| `servers/lloadd/lload.h` | backend/tier/connection/operation 状态与锁字段 | `LloadBackend` 286，连接状态 341，`LloadConnection` 386，`LloadOperation` 532 |
| `config.c` | standalone 配置解析、嵌入式 cn=config schema、动态失效处理的配置侧 | config table 184，objectClasses 796，动态 backend 3656 |
| `main.c` | standalone CLI、启动、signal、daemonize、清理 | `usage` 304，`main` 349 |
| `daemon.c` | listeners、I/O event bases、主循环、动态配置失效、signal | `lload_open_listener` 372，`lload_listener` 841，`lloadd_daemon` 1242 |
| `connection.c` | BER 读取、worker handoff、写缓冲/反压、连接回收 | `handle_pdus` 69，`connection_read_cb` 172，`connection_write_cb` 299 |
| `client.c` | client operation 分派、普通路由、ProxyAuthz、client 生命周期 | `request_process` 89，`handle_one_request` 343，`client_reset` 658 |
| `operation.c` | 双向 messageID map、Abandon、错误响应、operation timeout/counters | `operation_init` 134，`operation_abandon` 427，`connection_timeout` 541 |
| `bind.c` | simple/SASL/EXTERNAL Bind、Bind pin、WhoAmI 身份恢复 | 状态说明 128，`request_bind` 190，`finish_sasl_bind` 528 |
| `extended.c` | 本地 StartTLS 与其他 extended operation 分派 | `handle_starttls` 34，`request_extended` 125 |
| `backend.c` | DNS/connect、池容量、backend/tier 选择、重试 | `try_upstream` 289，`backend_select` 340，`backend_retry` 414 |
| `upstream.c` | upstream 初始化/Bind/TLS、响应转发、断线传播 | `handle_one_response` 190，`upstream_finish` 653，`upstream_unlink` 1060 |
| `tier*.c` | roundrobin、weighted、bestof 策略 | `roundrobin_select` 77，`weighted_select` 170，`bestof_select` 216 |
| `monitor.c` | 嵌入式 monitor schema、树、计数器、连接关闭接口 | schema 99，connection modify 556，open 1261 |
| `module_init.c` | slapd standalone backend 模块生命周期 | `lload_back_initialize` 150 |
| `epoch.c` | connection/operation 的 epoch 延迟回收 | `epoch_join` 110，`epoch_append` 241 |

### 2.1 对象关系

- `LloadTier` 按配置顺序组成单向队列，每个 tier 有一种选择策略和一组 backend：`lload.h:233-284`。
- `LloadBackend` 保存 URI/TLS、retry 状态、regular/bind/preparing/connecting 四类集合、池容量及统计：`lload.h:286-327`。
- `LloadConnection` 同时表示 client 或 upstream。`c_state` 表示 READY/CLOSING/ACTIVE/BINDING/DYING，`c_type` 表示 OPEN/PREPARING/BIND/PRIVILEGED：`lload.h:341-356`。
- 每个 client 和 upstream 都有一个 `c_ops` TAVL。一个 `LloadOperation` 同时记录 client/upstream connid、两个 messageID、原始 request/control BER、pin 和结果：`lload.h:473-496,510-560`。
- operation 转发时同时进入 client map 与 upstream map；最终响应、Abandon、断线或 timeout 从两侧解除：`client.c:request_process:203-270`，`operation.c:operation_unlink:231-368`。

### 2.2 affinity 状态

按优先级从低到高：

1. `NOT_RESTRICTED`：每个 operation 自由选 upstream。
2. `WRITE`：固定 backend，所有相关 write 完成后按 `write_coherence` 计时。
3. `BACKEND`：永久固定 backend。
4. `UPSTREAM`：永久固定具体连接。
5. `ISOLATE`：声明为固定并从池隔离，但头文件明确标注 TODO；实际主要按 UPSTREAM 路径处理。
6. `REJECT`：不转发。

枚举顺序本身就是 controls 中“最高动作优先”的比较依据：`lload.h:366-381`，`client.c:99-126`。

## 3. 配置 schema 与 daemon CLI

### 3.1 standalone 配置语法

配置按行解析，支持空白续行、`#` 注释、双引号和反斜线转义；tier 后续的 `backend-server` 归属于最后一个 tier。文档锚点为 `doc/man/man5/lloadd.conf.5:15-63`，解析入口是 `config.c:lload_read_config:2692`、`lload_read_config_file:2564`、`lload_config_fp_parse_line:3536`。

源码 config table 中的全局项如下：`config.c:184-688`。

| 类别 | 配置项 | 源码行为/默认 |
|---|---|---|
| 进程 | `argsfile`, `pidfile`, `include` | 参数文件、PID 文件、递归包含 |
| 线程 | `concurrency`, `threads`, `threadqueues`, `io-threads`, `max_pdus_per_cycle` | worker 默认由 slapd 常量给出；队列默认 1；I/O 默认 1；每轮 PDU **代码默认 10** |
| listener/缓冲 | `sockbuf_max_incoming_client`, `sockbuf_max_incoming_upstream`, `tcp-buffer`, `iotimeout` | 两侧 PDU **代码默认均为 16,777,215**；写超时默认 10,000 ms |
| 流控 | `client_max_pending`, `write_coherence` | 默认 0，分别表示无限制、无 write affinity |
| 路由 | `tier`, `backend-server`, `restrict_exop`, `restrict_control` | 见后文 |
| 身份 | `bindconf`, `feature` | production supported mask 只有 `proxyauthz` |
| TLS | `TLSCA*`, `TLSCertificate*`, `TLSCipherSuite`, `TLSCRL*`, `TLSRandFile`, `TLSVerifyClient`, `TLSDHParamFile`, `TLSECName`, `TLSProtocolMin` | 本地 client-facing TLS context；按 TLS 库/编译宏生效 |
| 日志 | `logfile`, `logfile-format`, `logfile-only`, `logfile-rotate`, `loglevel` | 共用 OpenLDAP logging 配置 |
| 遗留 | `gentlehup`, `idletimeout`, `restrict` | 被 parser 接受；后两者在 lloadd request/runtime 中无消费路径，`gentlehup` 只影响 signal flag |

源码默认值锚点：`lload.h:80-83`、`config.c:61-90`、`backend.c:lload_backend_new:703-723`。backend 默认：regular 1、bind 1、retry 5000 ms、weight 1、两个 pending limit 均 0（无限制）。

`io-threads` 被向下折算为不大于输入值的 2 的幂，最终用 `fd & mask` 分片；启动时还被 clamp 到 `SLAPD_MAX_DAEMON_THREADS`（默认 16）：`config.c:1017-1035`、`daemon.c:85-116,1268-1287`。

`feature` 的 parser 可识别 `proxyauthz`、条件编译的 `vc`、`read_pause`，但 `LLOAD_FEATURE_SUPPORTED_MASK` 仅含 `proxyauthz`。后两者会打印“experimental/unsupported”警告而不是拒绝：`lload.h:178-188`、`config.c:config_feature:2020-2075`。

`restrict_exop`/`restrict_control` 动作为 `ignore|write|backend|connection|isolate|reject`。特殊 exop OID `1.1` 设置未知 exop 默认动作：`config.c:1379-1517`。legacy `restrict` 只把词转换成临时 bitmask，函数返回前未保存到全局状态：`config.c:config_restrict:1943-1977`。

### 3.2 `bindconf` 与 backend 项

`bindconf` 是所有 regular upstream 共用的服务身份/网络配置：

`bindmethod=simple|sasl`、`binddn`、`saslmech`、`authcid`、`authzid`、`credentials`、`realm`、`secprops`、`timeout`、`network-timeout`、`keepalive=idle:probes:interval`、`tcp-user-timeout` 及一组 outbound TLS 参数。完整文档锚点：`lloadd.conf.5:687-789`；身份选择顺序为 authzId、authcId、`dn:` + binddn：`config.c:1274-1363`。

`backend-server` 参数：

- `uri=ldap[s]://host[:port]`，也支持编译条件下的 LDAPI；URI 必填。
- `numconns`、`bindconns`：均必须大于 0。
- `retry`：毫秒，允许 0。
- `max-pending-ops`：backend 总 in-flight 上限，0 无限。
- `conn-max-pending`：单 upstream in-flight 上限，0 无限。
- `starttls=no|yes|critical`；`ldaps://` 覆盖 StartTLS 设置。
- `weight`：供 weighted/bestof 使用。

锚点：`config.c:lload_backend_finish:1080-1147`、`backend_config_url:1151-1220`、`config_backend:1223-1271`、`backend_cf_gen:3656-3803`。

### 3.3 嵌入式 cn=config schema

`config.c:796-867` 定义三个 objectClass：

- `olcBkLloadConfig`：MUST `olcBkLloadBindconf`, `olcBkLloadIOThreads`, `olcBkLloadListen`, 两个 SockbufMax、MaxPDUPerCycle、IOTimeout；MAY features、TCP buffer、TLS、ClientMaxPending、WriteCoherence、RestrictExop/Control。
- `olcBkLloadTierConfig`：MUST `cn`, `olcBkLloadTierType`。
- `olcBkLloadBackendConfig`：MUST `cn`, URI、Numconns、Bindconns、Retry、两个 pending limit；MAY StartTLS、Weight。

动态 add/delete tier/backend 位于 `config.c:3817-3975`。在线变化的实际效果：

| 变化 | 固定源码行为 |
|---|---|
| add/delete tier/backend | pause 后更新结构、建立/关闭连接，并同步 monitor |
| pool 数量 | 尽量 gentle 缩池或补连接：`daemon.c:1540-1653` |
| backend URI/TLS 等 | reset 该 backend 全部连接后重建：`daemon.c:1524-1537` |
| `bindconf` | reset 所有 upstream 后重建：`daemon.c:1778-1801` |
| client-facing TLS 配置 | 终止已有 TLS client：`daemon.c:1753-1775` |
| listener | 值可持久化，但启动后只告警“restart 才生效”：`config.c:949-983` |
| `io-threads` | 启动后只告警“restart 才生效”；底层 invalidation 若被触发仍是 `assert(0)` 的未实现路径：`config.c:1017-1035`、`daemon.c:1700-1709` |

嵌入式模块使用 slapd pause/unpause 回调，让 event bases 停到 barrier 后应用变化：`module_init.c:71-85`、`daemon.c:1834-1902`。

### 3.4 standalone CLI

`main.c:usage:304-342` 与 `main:435-594`：

| 选项 | 行为 |
|---|---|
| `-4`, `-6` | 限制 listener 地址族（条件编译） |
| `-d level` | debug，且即使 level=0 也不 daemonize；`?` 列出级别 |
| `-f file` | standalone 配置文件 |
| `-h URLs` | listener URL 空格列表 |
| `-n name` | 服务/日志名 |
| `-o slp=...` | 条件编译的 SLP 配置 |
| `-s`, `-S`, `-l` | syslog 级别/严重级别/facility，受编译宏约束 |
| `-r dir` | chroot，受平台宏约束 |
| `-u user`, `-g group` | drop privileges，受平台宏约束 |
| `-t` | 校验配置后退出 |
| `-V`, `-VV` | 版本；第二次后退出 |

异常点：getopt 字符串包含 `c:` 与 `F:`，但 switch 没有相应 case，usage/man page 也未列出；传入会走 default usage/error：`main.c:435-452,588-594`。

standalone 启动顺序是先根据 `-h` 打开 listeners，再 chroot/drop privilege，再初始化并读取配置，然后 TLS、signal、daemonize、pid/args、主 daemon：`main.c:638-851`。这解释了 man page 对 `-r` 的提示：listener 在 chroot 前打开。

### 3.5 文档与代码不一致

1. man page 声称 client/upstream 最大 PDU 默认分别 262143/4194303：`lloadd.conf.5:325-332`；代码两者均是 `(1<<24)-1`：`lload.h:80-81`。
2. man page 声称 `max_pdus_per_cycle` 默认 1000：`lloadd.conf.5:353-359`；代码默认 10：`lload.h:83`、`config.c:86`。
3. man page 称 controls on extended operations 不检查：`lloadd.conf.5:394-403`；源码中未知 exop 最终调用 `request_process`，会检查 controls；只有本地 StartTLS 和 Bind 绕开该路径：`extended.c:125-171`、`client.c:99-127`。
4. man page 已注释掉 `gentlehup`/`idletimeout` 文档：`lloadd.conf.5:113-136`，但 config table 仍接受二者：`config.c:230-250`。

Go 兼容实现应以源码 oracle 结果为准，并把这些项目列为显式差分，不应照 man page 猜行为。

## 4. Listener 与 upstream 连接模型

### 4.1 listener

- 默认 URL 是 `ldap:///`：`daemon.c:lloadd_listeners_init:702-768`。
- 支持 LDAP/LDAPS/LDAPI 以及 PLDAP/PLDAPS（HAProxy PROXY protocol v2）；具体可用性取决于 TLS、local socket 编译宏：`lloadd.8:131-178`、`daemon.c:372-459`。
- 一个 URL 可经 `getaddrinfo` 展开成 IPv4/IPv6 多个 socket；TCP nonblocking、`SO_REUSEADDR`，IPv6 尝试 `IPV6_V6ONLY`，LDAPI 处理文件权限：`daemon.c:243-369,465-677`。
- listener 有独立 libevent base/thread；`LEV_OPT_THREADSAFE|LEV_OPT_DEFERRED_ACCEPT`，backlog 1024：`daemon.c:1030-1208`。
- accept 后按 `fd & lload_daemon_mask` 选择 I/O event base，设置 keepalive/TCP_NODELAY，必要时解析 PROXY v2，再创建 client：`daemon.c:lload_listener:841-954`。
- `EMFILE/ENFILE` 时临时 disable listener；任一连接释放后可重新 enable：`daemon.c:listener_error_cb:969-1000`、`listeners_reactivate:1003-1027`。
- PROXY v2 提供的地址只用于记录/日志，lloadd 本身不做 ACL：`lloadd.8:153-162`。

### 4.2 线程与 I/O

- 主线程/event base：signal、DNS、retry、tier stats、operation timeout。
- 一个 listener thread/event base：accept。
- N 个 I/O thread/event base：client 和 upstream socket。
- 一个 OpenLDAP worker pool：PDU 处理、connect task、服务 SASL Bind 等。

启动锚点：`daemon.c:lloadd_daemon:1242-1342`；worker pool 初始化：`init.c:169-203`。

`connection_read_cb` 先在 I/O thread 读取一个完整 LDAPMessage，然后交给 worker。worker pool 提交失败或 `max_pdus_per_cycle=0` 时，I/O thread 直接处理一个 PDU以保持进度：`connection.c:172-291`。worker 最多处理配置数量后把 read event 交回：`connection.c:handle_pdus:69-162`。

写侧每个 connection 有一个可追加 BER buffer `c_pendingber`。写阻塞会设置 `READ_PAUSE`、注册写事件和 `iotimeout`，写完再恢复读：`connection.c:299-382`。注意：client 写阻塞不会反向停止所有 upstream 响应读取；`upstream.c:180-183` 仍有 TODO，因此慢 client 可能让 client output BER 持续增长，是内存上限设计缺口。

### 4.3 upstream 建连与池化

建连状态机：

1. `backend_retry` 判断目标连接总数，任何时刻每 backend 只允许一个 opening 尝试：`backend.c:414-476`。
2. TCP 通过 libevent async DNS；固定源码只尝试返回链表的第一个 addrinfo，失败不轮询其余地址：`backend.c:upstream_name_cb:99-286`，特别是 130 行 TODO。
3. nonblocking connect 用 `network-timeout`，设置 keepalive、TCP_USER_TIMEOUT、TCP_NODELAY：`backend.c:140-220,479-615`。
4. 按 backend 配置完成 LDAPS 或 StartTLS：`upstream.c:upstream_tls_handshake_cb:736`、`upstream_starttls:810`。
5. 连接被分配为 regular 或 bind。regular 若配置 `bindconf` 则先服务 Bind；bind connection 保持未绑定，等待客户端 Bind：`upstream.c:upstream_finish:653-731`、`upstream_bind:573-647`。

池填充顺序优先确保至少一个 regular，再一个 bind，然后补 regular，最后补 bind：`upstream.c:663-706`。regular pool 可多 operation 复用；bind pool 的 connection 进入 BINDING 后不再可选。

upstream 断开时：所有 in-flight operation 向各 client 返回 `LDAP_OTHER`；固定到该 upstream 的 client 被置为 gentle closing；连接从池移除并立即触发补池：`upstream.c:linked_upstream_lost:50-62`、`upstream_unlink:1060-1144`。

## 5. Bind affinity 与身份状态

`bind.c:128-188` 是固定源码对状态机最完整的说明。

### 5.1 所有 Bind 的共同规则

- 仅接受 LDAPv3；其他版本返回 `LDAP_PROTOCOL_ERROR`：`bind.c:267-277`。
- 新 Bind 调用 `client_reset`，Abandon 当前 client 所有 operation，并清理当前 auth/SASL 状态：`bind.c:202-260`、`client.c:658-711`。
- Bind 期间 client 为 `LLOAD_C_BINDING`。除 Abandon 外的新 operation 返回 `LDAP_PROTOCOL_ERROR "bind in progress"`：`client.c:394-403`。
- Bind control 原样随 Bind 转发，但不经过 `restrict_control` 检查，也不会添加 lloadd ProxyAuthz：`bind.c:client_bind:90-103`。

### 5.2 Simple Bind

- 从 bind pool 选一个 READY connection；请求期间该 upstream 独占。
- lloadd 在请求发送前把候选身份记为 `dn:<bindDN>`；成功保留，失败清空：`bind.c:292-307`、`handle_bind_response:698-731`。
- anonymous simple Bind 使 `c_auth` 为空。
- upstream 原始 Bind result/control 恢复 client messageID 后转发。

### 5.3 SASL Bind

- 非 EXTERNAL 机制的多步交换使用 `pin_id` 把后续 Bind 固定到同一个 bind upstream：`bind.c:202-251,343-437`。
- 收到 `LDAP_SASL_BIND_IN_PROGRESS` 后，operation 以 msgid=0 作为内部 pin vessel 保留，下一步客户端 Bind 复用它：`bind.c:669-711`。
- SASL 成功且启用 ProxyAuthz 后，lloadd 暂不把成功结果给 client，而是在同一 upstream 发内部 WhoAmI，得到最终 authzid 后再转发原成功 Bind：`bind.c:finish_sasl_bind:528-588`、`handle_whoami_response:754-856`。
- 若 WhoAmI 不支持或协商出了客户端 SASL security layer，内部请求失败，客户端得到 `LDAP_OTHER`；源码注释明确用此检测不透明安全层：`bind.c:519-526,789-801`。

客户端侧可代理的 SASL 仅适合不依赖端到端 transport 元数据且不建立 integrity/confidentiality layer 的机制：`lloadd.conf.5:983-991`。这与 **服务账号** `bindconf` SASL 不同：服务账号连接终止在 lloadd，源码允许在 regular upstream 上安装 SASL security layer：`upstream.c:sasl_bind_step:314-440`。

### 5.4 SASL EXTERNAL

- 在 lloadd 本地处理，不发送客户端 Bind 到 upstream。
- 只接受空 credentials（隐式 assertion）；显式 authzid 返回 `LDAP_UNWILLING_TO_PERFORM`。
- 从当前 TLS peer certificate 取 DN，保存为 `dn:<peerDN>`；无 TLS/无证书返回 invalidCredentials 或 authMethodNotSupported：`bind.c:bind_mech_external:30-86`。

### 5.5 ProxyAuthz 与 privileged client

- 启用 `feature proxyauthz` 时，普通转发 operation 前置 critical RFC 4370 control，值为 client `c_auth`：`client.c:297-320`。
- 若 client 身份与 `lloadd_identity` 大小写不敏感字符串相等，则标记 PRIVILEGED，不添加该 control。这里不做 DN normalization：`bind.c:75-77,722-725,840-843`、`lloadd.conf.5:145-155`。
- client 自己提供 ProxyAuthz 时，lloadd 不去重；会再前置一个。官方 SASL 测试期望 upstream 返回“proxy authorization control specified multiple times”：`tests/scripts/lloadd/test006-sasl:178-204`。

### 5.6 两个必须固定测试的源码疑点

1. `client_reset` 清除了 `c_backend`/`c_linked_upstream`，但未把 `c_restricted` 复位为 `NOT_RESTRICTED`：`client.c:658-711`。这与注释/man page“Bind 清除 limitation”冲突，并可能使 Bind 后下一个 operation 看到 restriction 与空指针不一致。必须用同一 TCP client 做 `control pin -> Bind -> Search` oracle 测试。
2. 在线修改 `bindconf` 后重新评估 privilege 使用 `privileged = ber_bvstrcasecmp(...)`，随后非零时设 PRIVILEGED，看起来与其他位置的 `!ber_bvstrcasecmp` 相反：`daemon.c:1792-1801`。这是疑似反向判定，必须保留成 oracle 差分项，不应直接照抄或擅自修正。

## 6. Search 与写操作路由

### 6.1 原始 BER 转发

`operation_init` 只解析外层 messageID、protocolOp tag、request BER 切片和 controls 切片：`operation.c:134-206`。普通转发：

- 为 upstream 分配 `c_next_msgid++`；
- 在 client/upstream 两个 TAVL 中建立映射；
- 重建 LDAPMessage 外壳，protocolOp value 和 controls 原样写入；
- 必要时前置 ProxyAuthz。

锚点：`client.c:request_process:203-323`。因此 DN/filter/attributes/modify values 不被解释、规范化或重写。

### 6.2 Search/Compare

- Search、Compare 和其他普通 operation 使用同一选择器。
- SearchEntry、SearchReference、IntermediateResponse 是非终态，逐个恢复 messageID 后转发；其他响应默认视为终态：`upstream.c:handle_one_response:190-309`。
- first-response latency 记录在 backend，供 bestof 使用：`upstream.c:256-270`。
- lloadd 不合并多个 backend 的 Search，不重排 entry，不解释 referral，也不校验 root DSE 宣告的 controls/extensions/SASL mechanisms。

### 6.3 Add/Modify/Delete/ModifyDN 与其他写

`write_coherence != 0` 时，除 Search/Compare 之外所有进入 `request_process` 的 operation 都先按 WRITE 处理：`client.c:128-133`。Bind、Abandon、Unbind、本地 StartTLS 已在其他分支处理；因此 Add/Delete/Modify/ModifyDN 以及未被本地处理的 exop 都属于该默认集合。

- 首个 write 选中 backend 后，后续 operation 立即固定到同一 backend，不要求同一 connection：`client.c:273-294`。
- timer 在所有 WRITE in-flight 完成后开始；有最后响应则取其时间，否则取请求开始时间：`operation.c:285-297`。
- 正值到期后下一次请求解除；负值永久保持；0 禁用：`client.c:143-177`。
- 该机制不选择 writable master，不做复制状态检测，不保证 read-your-writes 已在副本间完成；它只保持同一 backend。

### 6.4 tier/backend/upstream 选择

选择顺序：当前 client 的 upstream affinity -> backend affinity -> 从第一 tier 起依次选择。`client.c:143-190`。

backend 选择规则：

1. backend 总 in-flight 达 `max-pending-ops`，返回“有候选但 BUSY”。
2. Bind 选 bind pool，其他选 regular pool。
3. pool 为空表示该 backend 当前 UNAVAILABLE，继续同 tier/后续 tier。
4. pool 非空但所有连接 BINDING/写缓冲未清/达到 conn limit，表示 BUSY。

锚点：`backend.c:try_upstream:289-337`、`backend_select:340-387`。

重要 tier 规则：一个 tier 只要存在相应 pool，即使全部 busy，也会停止，不进入下一 tier；只有整个 tier 没有建立合适连接才 fallback 到后续 tier：`backend.c:upstream_select:390-407`、`lloadd.conf.5:670-681,791-800`。

策略：

- `roundrobin`：backend 成功选择后轮转起点；backend 内 connection 也轮转：`tier_roundrobin.c:77-118`、`backend.c:312-318`。
- `weighted`：按 RFC 2782 类似算法随机排序；零权重仍有小概率：`tier_weighted.c:54-95,170-207`。
- `bestof`：按 time-to-first-response 的滚动 weighted fitness，从随机两个 backend 中选较优，失败后 round-robin fallback：`tier_bestof.c:165-213,216-310`。其 weight 越大越不利，与 weighted 的方向相反。
