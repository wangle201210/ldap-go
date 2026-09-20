# 已实现功能的 OpenLDAP 行为核验

核验基准为 OpenLDAP **2.6.13**，源码提交
`d172686d3d270bc961b78f3ff00d7019c8dfb094`。本页补充
[功能兼容矩阵](compatibility.md)，不把功能已经实现、测试通过和所有行为完全一致
视为同一件事。

## 判定标准

- **实测一致**：对独立启动的两端执行相同请求，比较结果码、返回数据、响应控制、
  连接状态及最终目录状态；结论只适用于该测试覆盖的配置和操作组合。
- **已知差异**：测试分别断言两端结果，或文档明确说明扩展和安全约束。
  这类测试通过表示差异没有意外变化，不表示两端相等。
- **未证明一致**：只有本地测试、源码契约、编译验证或部分组合的对照。
  不可从单一场景推导全部后端、Overlay 顺序、复制拓扑和平台都一致。

业务数据比较允许规范化 LDAP 不保证的条目、属性及普通多值顺序。
排序请求必须另外检查顺序。分页 cookie、随机盐、时间戳和自动生成 UUID 等
不能简单逐字节比较，必须验证它们对应的行为。相同 SDK 测试会忽略诊断文本及
密码哈希字节，不替代原始 BER、命令行或密码重新 Bind 测试。

## 2026-09-20 新增核验与修复

本轮在已有测试之外确认并修复了四类非预期差异：

| 场景 | 修复内容 | 回归证据 |
| --- | --- | --- |
| 缺失属性与无效过滤断言组合 | 保留 LDAP Undefined，防止 NOT 将非法断言转为匹配；有效但缺失的属性仍为 False。 | [84 个原生组合](../internal/server/openldap_filter_absent_attribute_test.go)、[普通 CI 断言测试](../internal/schema/filter_assertion_test.go) |
| 管理员 Delete+Add 修改密码 | 管理员按存储值匹配删除哈希；普通用户仍按 ppolicy 校验明文旧密码。失败不会改变密码及策略时间。 | [两端 8 个场景](../internal/server/ppolicy_admin_modify_reference_test.go) |
| syncrepl 父条目改名 | 同一事务移动已有子孙条目并更新父条目和 cookie，保留子条目 UUID/CSN；目标冲突整体回滚。 | [原生 provider 到 bbolt](../internal/server/syncrepl_subtree_rename_openldap_test.go)、[冲突回滚](../internal/server/syncrepl_subtree_test.go) |
| rewrite 歧义与重复捕获 | Linux 使用经 glibc 对照的捕获选择；BSD 路径保留迭代历史并清除重复分组中的过期子捕获，保留工作预算。 | [双平台各 23 个 `:C` 原生用例](../internal/server/rwm_rewrite_capture_reference_test.go)，两端各 46 项完整 RWM 顶层测试通过 |

这也说明此前已有的全量回归不能证明所有未覆盖组合正确。新增四个原生回归被纳入
严格套件的必跑清单，不能通过跳过测试获得成功结果。

Linux 实跑还修复了两处运行和运维检查问题：

- purego/fakecgo 环境下，Linux 权限切换改用 libc 的全线程凭据同步接口，
  不再触发 `AllThreadsSyscall` panic。root 子进程检查已有、新建线程的
  UID/GID/附加组及不可恢复 root；全程 `CGO_ENABLED=0`。
- 生产权限检查同时检查 root 所有符号链接指向路径的祖先权限，避免漏掉
  可被其他用户写入的目标目录。此检查是 ldap-go 的运维能力，不是原生 LDAP 协议。

修正的测试环境条件没有改变预期业务结果：写超时使用足够大的响应和可排空的
接收窗口；原生 SHA-2 模块编译关闭严格别名优化并校验标准摘要；SQL 两端使用
ODBC 可执行的独立取键查询，继续比较相同的结果码、数据库状态和回滚。

### 原生 3DES 对照阻塞

本机 macOS 的 Cyrus SASL 2.1.28_2 / OpenSSL 3.6.2 在 DIGEST-MD5
SSF 112 路径发生原生空指针崩溃。独立的“原生 ldapwhoami → 原生 slapd”
同样崩溃，SSF 1、55、128 对照成功，因而不能将这一失败归因于 ldap-go。
源码显示 `init_3des` 可返回失败，部分调用路径仍继续使用未初始化的上下文；
未进一步断言其初始化失败的具体底层原因。

Linux/arm64 的 Debian Bookworm 原生环境（Cyrus 2.1.28+dfsg-10、
OpenSSL 3.0.20）在同一 SSF 112 独立测试中返回
`couldn't init cipher '3des'`，LDAP 结果码 80。
这一原生互操作用例仍未通过，不能把本地算法向量通过写成原生互操作已经验证。
严格门槛继续保留失败，不降级为通过或跳过。

### 最终验证记录

生产代码冻结于 `afdc90f`（包含 `48f9028`、`bb051c9`）；随后仅补齐工具发现、
测试门槛、CI 和文档。所有 Go 构建与测试使用 `CGO_ENABLED=0`。

| 验证 | 结果 |
| --- | --- |
| 最终全仓 Go 测试、`go vet` | 通过 |
| 六平台编译 | Linux amd64/arm64、Darwin amd64/arm64、Windows amd64、FreeBSD amd64 通过；不等于各平台运行行为完全一致 |
| Linux/arm64 完整严格套件 | 2,437 条顶层 Test 通过记录、1 条失败、11 条跳过；失败为上述原生 3DES 初始化问题，整体命令返回失败 |
| 补跑 Linux 工具发现空缺 | 修正 `saslpluginviewer` 名称、SASL 插件目录及客户端硬编码 Homebrew 路径后，SCRAM-PLUS、ldapcompare、ldapexop 三项在 Linux 和 macOS 均通过；不将它们伪装成之前完整运行中已执行 |
| `allowed` / Verify Credentials 容器对照 | 两个顶层测试通过；`allowed` 的 80 组相等与 6 组预期 ACL 差异分开统计 |
| 完整安装的 macOS OpenLDAP 2.6.13 客户端 | host/port、SASL quiet、URI list、ldapurl 四组补充对照通过；ldapurl 的 GNU getopt 输出未据此获得兼容声明 |
| RWM 定向模糊测试 | 5 秒、11,838 次执行通过；不是穷举输入证明 |

完整套件还会按前置条件跳过 Cyrus 源码契约和另行提供 VC 模块端点的客户端
集成等可选测试。单独补跑和源码/单元测试不能被算成一次“无跳过全通过”。

本地保留的主要日志：

- `/tmp/ldap-go-compatibility-linux-verified-20260920-tests.log`：完整 Linux 运行。
- `/tmp/ldap-go-compatibility-linux-discovery-20260920.log`：三项工具发现补跑。
- `/tmp/ldap-go-compatibility-docker-20260920.log`：两个容器对照。
- `/tmp/ldap-go-compatibility-final-local-20260920.log`：最终全仓 Go 测试。
- `/tmp/ldap-go-native-3des-audit-20260920/result.log`：独立纯原生 3DES 复现。

临时日志不是仓库内永久资产。后续复现使用下面的脚本和 nightly 上传的日志，
每次重新报告实际失败、跳过及预期差异。

## 已知不同的行为

以下是现有实现中已经记录的具体差异，不是未实现功能清单。原生程序的缺陷也可能
被客户端观察到，因此不能因为 ldap-go 的结果更严格就将其算作“相同”。

| 范围 | 差异与影响 | 现有证据 |
| --- | --- | --- |
| `allowed`、`deref` 的值级 ACL | ldap-go 过滤被拒绝的值；原生部分缓存或响应路径仍会泄露相关值。 | [allowed 对照](../internal/server/allowed_reference_test.go)、[deref 对照](../internal/server/openldap_deref_test.go) |
| SQL Tree Delete 中途权限失败 | ldap-go 拒绝并回滚完整子树；原生部分场景可能返回成功并留下删除前缀。 | [Tree Delete 说明](compatibility.md#controls-and-extended-operations) |
| `collect` 属性写保护 | ldap-go 检查每项修改和带选项的基础属性，阻止原生的绕过组合。 | [collect 对照](../internal/server/openldap_collect_test.go) |
| `@objectClass` pre/post-read 选择器 | ldap-go 按 RFC 接受；原生 2.6.13 返回未定义属性错误。普通 Search 选择器另有一致性对照。 | [选择器对照](../internal/server/openldap_objectclass_attribute_selection_test.go) |
| Cancel 的畸形值和自取消 | ldap-go 拒绝尾随字节、自取消返回 `cannotCancel`；原生接受这些边界输入。 | [Cancel 边界](compatibility.md) |
| 别名解引用超过深度 | ldap-go 返回 `aliasDereferencingProblem`；原生部分路径意外返回成功并附带错误诊断。 | [别名边界](compatibility.md) |
| `retcode` 的目录内扩展操作 | ldap-go 只发送一个合法 ExtendedResponse；原生可发送重复、非法响应序列。 | [retcode 对照](../internal/server/openldap_retcode_test.go) |
| `olcRootDSE`、`olcSecurity` 在线删除或替换 | ldap-go 原子更新配置和运行时；不保留原生部分字段删除后仍生效或无法删除的状态。 | [Root DSE 配置](../internal/server/root_dse_configuration_test.go)、[安全配置对照](../internal/server/openldap_security_requirements_test.go) |
| 手工构造的 PBKDF2 哈希 | ldap-go 限制迭代成本，并拒绝某些原生接受的异常格式。 | [密码模块对照](../internal/server/openldap_pbkdf2_password_test.go) |
| OTP 首次并发重放 | ldap-go 原子检查并更新重放状态；不复刻原生分离检查和更新的竞争窗口。 | [OTP 范围](compatibility.md#overlays) |
| `nestgroup` 等资源边界 | ldap-go 对图遍历及资源消耗设置明确上限，超过时拒绝请求。 | [Overlay 范围](compatibility.md) |
| `ldapvc` 客户端 | 内层密码验证失败时 ldap-go 返回非零退出码；原生可返回零。匿名请求的认证字段编码也不同。 | [CLI 对照](../cmd/ldap-go/client_verify_credentials_external_test.go) |
| 非默认 `olcThreads` 等配置 | 原生调整线程；ldap-go 拒绝不支持的值，不将其当成无效果配置接受。 | [配置 Schema 对照](configuration-schema.md) |
| Darwin 忽略大小写的特殊重复捕获 | 默认忽略大小写模式下，`^((a)\|b)*$` 匹配 `ab` 的 `$1/$2`，原生得到 `b/ab`，ldap-go 得到 `b/`。上述 23 例使用 `:C`，没有证明此模式完全相同；musl 捕获语义也未验证。 | [捕获实现与范围](../internal/server/rwm_rewrite_regex.go) |

SM3/TLCP、逐次密码哈希选择控制、bbolt 在线备份扩展和 Web 管理页面是本项目
能力，不存在可据此直接声称逐项相同的原生 OpenLDAP 页面或默认功能。
MDB 文件格式和新增第三方模块仍是项目明确排除项。

SASL PLAIN 不执行 Simple Bind 的 `ppolicy` 锁定和过期策略，是已实测的
**两端一致边界**，不是上述差异之一。依赖这些策略的普通用户应按
[部署说明](operations.md#password-policy-authentication)配置 TLS + Simple Bind。

## 复现

```sh
CGO_ENABLED=0 OPENLDAP_ENV_FILE=/path/to/openldap-reference.env \
  LDAP_GO_OPENLDAP_TEST_LOG=/path/to/openldap-tests.log \
  ./scripts/test-openldap-full.sh

CGO_ENABLED=0 OPENLDAP_ENV_FILE=/path/to/openldap-reference.env \
  ./scripts/test-openldap-sdk.sh

CGO_ENABLED=0 OPENLDAP_SOURCE=/path/to/openldap-git \
  LDAP_GO_OPENLDAP_ALLOWED_DOCKER_TESTS=1 \
  LDAP_GO_OPENLDAP_VC_DOCKER_TESTS=1 \
  go test ./internal/server -count=1 -timeout=30m -v \
  -run '^(TestOpenLDAPAllowedReference|TestOpenLDAPVerifyCredentialsReference)$'
```

第三条命令使用可丢弃容器编译原生对照服务器，不将 C 代码链接到 ldap-go。
完整严格套件包含本地、源码契约和原生对照测试，其顶层通过数量不能称作
“完全一致的功能数量”。跳过项和预期差异必须单独核对。

Nightly CI 分别保留严格套件的完整逐项日志和两个容器对照的日志。
`allowed` 两种放置方式各有 40 组精确一致、3 组明确断言的 ACL 缓存差异；
不能将全部 86 组报告为相等。
