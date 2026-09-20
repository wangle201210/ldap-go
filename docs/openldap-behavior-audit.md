# 已实现功能的 OpenLDAP 行为核验

参考版本为 OpenLDAP **2.6.13**，源码提交
`d172686d3d270bc961b78f3ff00d7019c8dfb094`。

本轮按用户确认的范围处理：**排除安全和数据完整性缺陷，其余已知业务差异对齐**。
不复制权限泄露、失败后部分提交、悬空内存读取或无界资源消耗。
功能范围仍以[兼容矩阵](compatibility.md)为准；MDB 文件格式及新增第三方模块不在复刻范围。

## 已收敛的差异

| 功能 | 当前行为与证据 |
| --- | --- |
| 缺失属性上的无效过滤断言 | 保留 LDAP Undefined，NOT 不会错误匹配；[84 个原生组合](../internal/server/openldap_filter_absent_attribute_test.go)。 |
| 管理员 Delete+Add 改密 | 按存储值删除旧哈希，普通用户仍执行密码策略；[原生与本地回归](../internal/server/ppolicy_admin_modify_reference_test.go)。 |
| syncrepl 子树改名 | 父条目、已有子孙条目及 cookie 同事务更新，子条目 UUID/CSN 不变；[原生 provider 对照](../internal/server/syncrepl_subtree_rename_openldap_test.go)。 |
| rewrite 捕获 | 对齐 Linux/glibc 和 Darwin 的已测捕获语义，涵盖默认模式、`:C`、歧义、重复、嵌套和共享结束标签；[双平台各 114 个用例](../internal/server/rwm_rewrite_capture_reference_test.go)。 |
| Cancel | 对齐自取消、尾随数据、原生接受的 BER 编码、结果码和诊断；保留请求边界、长度和整数界限，取消不能跨连接；[30 个原生边界用例](../internal/server/openldap_cancel_boundaries_test.go)。 |
| critical pre/post-read 的 `@objectClass` | 修改前返回原生 `undefinedAttributeType`，目录数据保持不变；[对照及失败原子性验证](../internal/server/openldap_objectclass_attribute_selection_test.go)。 |
| 别名深度边界 | 对齐深度零和成功中间查找后的原生结果码、matchedDN、诊断和条目集；深度限制及 ACL 保持生效；[32 个组合](../internal/server/openldap_alias_depth_test.go)。 |
| `olcRootDSE` 在线修改 | 对齐原版拒绝删除、替换的结果码及诊断，包括空属性、部分删除、数值 OID 和多值情况；[16 步原生对照](../internal/server/openldap_root_dse_modify_test.go)及本地同批修改回滚验证。ADD 保持可用。 |
| `retcode` 目录内 Password Modify | 对齐内部 SearchResultEntry 与实际 ExtendedResponse 的包序列，实际改密、错误旧密码、ACL 过滤和后续消息 ID；[12 个原生场景](../internal/server/retcode_password_modify_reference_test.go)。 |
| PBKDF2 导入格式 | 对齐空白、正号、十进制数字前缀、额外字段和 NUL 终止；正确与错误密码均比较真实 Bind；[双平台各 104 个组合](../internal/server/openldap_pbkdf2_password_test.go)。 |
| `ldapsearch -H` | 默认与原版一样用于连接目标；完整 URL 搜索须显式指定 `-url-search`；[16 组原生场景](../cmd/ldap-go/client_url_test.go)。 |
| `ldapvc` | 默认退出码依外层 LDAP 结果，省略操作数时编码与原版一致；显式空 DN、空密码用于匿名验证；[请求及退出码精确比较](../cmd/ldap-go/client_verify_credentials_external_test.go)。 |
| Linux 运行与检查 | 修复纯 Go/fakecgo 环境下的降权 panic，验证所有现有及新建线程的凭据；修复权限检查遗漏符号链接目标祖先的问题。这些是运行正确性改进。 |

此前依赖 ldap-go 扩展默认行为的脚本需注意：

- 完整 RFC 4516 URL 搜索使用 `ldapsearch -url-search -H ...`。
- 要求内层验证失败也返回非零时，使用 `ldapvc -require-verified ...`。
- 匿名 VC 验证传入两个明确的空操作数 `'' ''`。省略操作数会复刻原版缺失认证字段的请求，原生模块会拒绝它。

详见[操作指南](operations.md)。

## 保留的安全例外

这些不计作“两端完全相同”，也不通过放宽测试掩盖：

| 范围 | 保留行为 |
| --- | --- |
| `allowed`、`deref` | 逐值执行 ACL，过滤原生部分路径会泄露的值。 |
| SQL Tree Delete、`retcode` 模拟 Modify 失败 | 报告失败时完整回滚，不复制原生失败后仍提交全部或部分写入的缺陷。 |
| `collect` | 检查每项修改及带选项的基础属性，阻止写保护绕过。 |
| 非关键 read-control 的未识别选择器 | Go 持有名称并做确定的 schema/ACL 投影。原生 `parseReadAttrs` 的 `ber_scanf("{M}")` 借用名称在 `ber_free(ber, 1)` 后仍被使用，其结果取决于分配器；不以这条路径的输出作精确对照。安全例外由[固定源码校验](../internal/server/openldap_read_control_lifetime_test.go)约束，不执行内存错误复现。 |
| `olcSecurity` 和配置失败回滚 | 成功提交的配置与运行时保持一致，不保留原生安全设置删除后仍使用旧值或失败后只发布部分运行状态的缺陷。`olcRootDSE` 的正常拒绝行为已经对齐，不作为例外。 |
| PBKDF2、嵌套组及协议资源 | PBKDF2 保留 1,000,000 次计算上限、4 KiB 编码边界、负数/溢出防护和恒定时间比较；图遍历、BER 和并发资源仍有上限。 |
| OTP 并发重放 | 检查与更新时间原子化，不复制原生检查和更新之间的竞争窗口。 |

非默认原生线程调度选项未实现时继续明确拒绝；“Schema 中存在该字段”不表示已实现运行行为。
SM3/TLCP、逐次密码哈希选择控制、bbolt 在线备份和 Web 页面属于项目能力，
没有对应的默认原生 OpenLDAP 功能可供逐项相等比较。

## 3DES 参考环境

原版 Cyrus 2.1.28 的 DES 奇偶校验问题使本机原生 3DES 无法完成验证：
macOS 出现空指针崩溃，Linux 返回 `couldn't init cipher '3des'`。
原生客户端到原生服务的自检也会失败，不能据此修改 Go 密码逻辑。

[专项脚本](../scripts/test-cyrus-3des-reference.sh)只在临时目录构建参考插件，
使用固定 Cyrus 源码及一个[公开记录的奇偶校验补丁](../scripts/fixtures/cyrus-sasl-2.1.28-des-parity.patch)。
OpenLDAP 源码不变，Go 生产实现不链接 Cyrus，也不使用 cgo。
补丁不改变有效密钥位；先通过纯原生自检，再比较 Go 与原生的双向交互。
双平台各 11 个原生/互操作子场景通过，无跳过。

完整回归通过 `LDAP_GO_CYRUS_3DES_REFERENCE_DIR` 仅为三个 DIGEST-MD5 测试选择此插件；
其它 SASL 测试保留普通参考环境。测试验证来源记录和修补后源码摘要，并输出参考类型。
**这是声明了参考插件修补的结果，不是未修改 Cyrus 的通过结果。**

## 验证范围

- 最终全仓 Go 测试通过，所有 Go 构建和测试均使用 `CGO_ENABLED=0`。
- Linux/arm64 最终严格套件通过，2,460 个顶层 Test 通过、零失败；macOS/arm64 严格套件 2,455 个顶层 Test 通过，随后新增的 Root DSE 专项及配置回归也通过。不将平台编译当作运行验证。
- 最终全仓 `go vet`、六平台编译、脚本检查和 nightly 工作流检查通过。
- `allowed` 和 Verify Credentials 容器对照通过。`allowed` 为 80 组精确一致、6 组明确 ACL 安全差异。
- RWM 双平台各 47 项定向顶层测试通过，20 秒 fuzz 的 29,583 次执行通过。
- 普通套件会如实报告依赖条件不满足的可选测试。仅 root 可执行的场景由 Linux root 运行及 nightly 的独立 root 步骤验证。
- 计数包含本地、源码契约及原生对照测试，不能当作“完全一致的功能数量”。排序不保证的集合可规范化；cookie、随机盐、UUID 和时间戳需比较对应行为，而非原始字节。
- 未穷举所有输入、Overlay 顺序、驱动、libc、语言环境和平台组合；musl、FreeBSD 没有新增原生运行证据。

## 复现

先准备固定原生环境（明确不执行测试）：

```sh
CGO_ENABLED=0 OPENLDAP_ENV_FILE=/path/to/openldap-reference.env \
  LDAP_GO_OPENLDAP_PREPARE_ONLY=1 ./scripts/test-openldap-full.sh
```

构建并验证隔离的 3DES 参考插件，产物目录必须尚不存在：

```sh
OPENLDAP_ENV_FILE=/path/to/openldap-reference.env \
  CYRUS_3DES_ARTIFACT_DIR=/path/to/new-cyrus-reference \
  ./scripts/test-cyrus-3des-reference.sh
```

运行完整对照并保留逐项日志：

```sh
CGO_ENABLED=0 OPENLDAP_ENV_FILE=/path/to/openldap-reference.env \
  LDAP_GO_CYRUS_3DES_REFERENCE_DIR=/path/to/new-cyrus-reference \
  LDAP_GO_OPENLDAP_TEST_LOG=/path/to/openldap-tests.log \
  ./scripts/test-openldap-full.sh
```

省略 `LDAP_GO_CYRUS_3DES_REFERENCE_DIR` 可重现未修改提供方的结果，包括其原生 3DES 故障。
Nightly 保存逐项日志、参考来源记录、补丁和构建/互操作日志。历史失败记录仍可在版本历史中查看。

本轮本地日志包括 `/tmp/ldap-go-final-parity-linux-20260920-tests.log`、
`/tmp/ldap-go-safe-parity-final-macos-20260920-tests.log`、
`/tmp/ldap-go-rootdse-final-macos-20260920.log` 和
`/tmp/ldap-go-final-parity-local-20260920.log`。临时日志不作为仓库内永久资产，
后续验证以同样的复现命令及 CI 上传的日志为准。
