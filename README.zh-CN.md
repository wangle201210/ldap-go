# ldap-go

[English](README.md) | [简体中文](README.zh-CN.md)

`ldap-go` 是一个使用 Go 实现的 LDAPv3 目录服务器，目标是与 OpenLDAP
2.6.x 保持行为兼容和 LDIF 数据兼容。项目包含持久化目录服务、兼容
OpenLDAP 风格的客户端与离线工具、LDAP 负载均衡器，以及支持中英文切换的
Web 管理控制台。

项目仍在持续开发中，并非 OpenLDAP 的完整替代品。实际支持范围以
[兼容性矩阵](docs/compatibility.md)为准。

面向学校、公司日常目录服务的
[常用功能验收](docs/common-production-scope.md#practical-acceptance-on-2026-09-20)
已通过：一万条用户数据的导入、查询、分页与持久化，故障恢复、单写复制恢复、
备份还原、Web 管理，以及使用同一 SDK 的 OpenLDAP 差异测试。
这代表明确范围内的功能验收，不代表全部 OpenLDAP 功能一致或任意部署的容量保证。

## 明确不复刻的范围

- **OpenLDAP MDB/LMDB**：不复刻其存储引擎、原生数据库文件及索引格式。
  ldap-go 使用 bbolt，目录数据通过 `slapcat` LDIF 迁移，不直接复制 MDB 文件。
- **第三方模块**：不再新增第三方模块的复刻，也不兼容其原生模块加载 ABI。
  已有的纯 Go 实现继续保留，实际支持范围见[模块覆盖清单](docs/openldap-module-coverage.md)。

以上是明确的项目范围排除项，不作为待补齐功能，也不计入其余复刻目标的完成度缺口。

## 主要能力

- LDAPv3 Bind、Search、Compare、Add、Modify、Delete、ModifyDN、StartTLS、
  Password Modify、常用控制、别名、引用和事务。
- 基于 bbolt 的持久化，以及原子 LDIF 导入导出、备份、恢复、重建、完整性
  检查、在线备份和备份保留策略。
- 在明确测试范围内兼容 OpenLDAP `cn=config`、Schema、ACL、Overlay、
  Replication、Monitor、代理和离线工具。
- 支持 Simple Bind、SASL PLAIN/CRAM-MD5/DIGEST-MD5/SCRAM/GSSAPI/EXTERNAL、
  TLS、LDAPS、LDAPI 和 GB/T 38636 TLCP。
- 支持 OpenLDAP 密码方案、SM3、加盐 SM3、PBKDF2-SM3 及已覆盖的 contrib
  密码模块。
- 遵循 LDAP ACL 的 Web 管理控制台，界面支持英文和简体中文。
- 使用固定版本 OpenLDAP 2.6.13 进行差异测试。

完整实现声明和边界见[实现状态](docs/implementation-status.md)。

## 性能对比

最新常用功能对照：2026-09-24 第五轮，100,000 个用户，基线 `b7e6cc1` 与最终
`final` 可执行文件对照，Apple M1 Pro，Go 1.26.4 禁用 cgo，OpenLDAP 2.6.13。
主表每行是三次重复测量的批次总耗时中位数，逐请求轮换服务端；仅计 SDK 调用时间，
结果校验不计时。各服务端均配置 uid/member/objectClass 等值索引。
相对性能为 `OpenLDAP / ldap-go × 100%`，100% 表示持平。使用频率是常见认证/目录
场景的定性估计，不是实际流量统计。SSHA/明文密码方法及不同成员数量分别统计。

| 常用功能 | 典型使用频率 | 次数 | ldap-go，默认权限 | OpenLDAP，默认权限 | 默认权限相对性能 | 显式 ACL 相对性能 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 用户 Bind，SSHA | 极高 | 1,000 | 115.10 ms | 91.92 ms | 79.9% | 78.8% |
| 非管理员 Base，热点用户 | 高 | 1,000 | 106.38 ms | 81.51 ms | 76.6% | 76.1% |
| 非管理员索引查询，热点用户 | 极高 | 1,000 | 110.49 ms | 82.17 ms | 74.4% | 80.6% |
| 直接所属组查询 | 高 | 100 | 20.92 ms | 13.23 ms | 63.2% | 60.0% |
| 读取千人成员组 | 中 | 100 | 107.18 ms | 98.62 ms | 92.0% | 84.0% |
| 嵌套组，客户端 BFS | 中～高 | 100 次遍历 | 69.23 ms | 46.36 ms | 67.0% | 66.1% |

[R5 常用功能报告](docs/common-ldap-performance.md)包含基线/当前/原生完整表格、
准确 ACL、原始样本和验证记录。显式 ACL 的热点 Base/等值查询耗时下降
**5.4%/8.7%**；直接所属组查询在显式 ACL 下下降 **38.6%**，默认权限下下降
**3.0%**。默认权限热点查询和 SSHA Bind 基本持平。**未达到 OpenLDAP 整体持平，
也不能声称所有负载都加速。**

首次显式 ACL 分散等值查询慢了 **10.8%**，基线/当前/原生为
197.20/218.43/129.65 ms。另一次七重复复查为 128.53/120.79/83.05 ms，
耗时下降 **6.0%**；两个结果分别保留，不混合或替换。显式 ACL 的管理员并发
查询首次慢了 **16.8%**，报告同样保留该结果。单独七批次并发复查的基线/当前/原生
中位数为 **292/276/259 ms**，范围为 **195–419/196–568/203–355 ms**。
首次回退没有在复查中持续出现；波动较大，两个结果分别保留，不声称稳定的并发加速。

最终生产改动仅包含投影描述符借用、纯 ACL 分支跳过未请求属性，以及受只读条件
保护的运行时数据库指针复用。最终选中数据仍有独立所有权，ACL 仍使用完整条目，
两次认证存储 View 均保留。TCP 读缓冲实验已否决并移除。完整 Go 测试、vet 和
355 条原生 PASS 记录均通过；已在原始基线复现的 Web Admin 纳秒定时竞态仅修复
测试夹具，没有修改 Web 生产逻辑。R2 已有操作属性兼容缺口继续保留说明。

[SDK 对照工具](internal/cmd/ldapcommonbench/README.md)可对临时服务复跑，
[第四轮归档](docs/common-ldap-performance-20260924-r4.md)保留前轮证据。
计时边界和组夹具与[早期完整操作对照](docs/performance-optimization-20260923-round13.md)
不同；写入、分页、并发和内存测量仍参考该报告。

## 环境要求

- Go 1.26 或更高版本。
- 生产二进制使用 `CGO_ENABLED=0` 构建，不需要 C 编译器。
- OpenLDAP 客户端工具仅在手动互操作测试时需要。
- Node.js 和 Chromium 仅在运行 Web 管理端浏览器测试时需要。
- 构建固定版本 OpenLDAP 差异测试环境所需的原生依赖见
  [测试文档](docs/testing.md)。

## 快速开始

编译程序、导入示例目录并启动 LDAP 监听：

```sh
mkdir -p ./bin ./data
CGO_ENABLED=0 go build -o ./bin/ldap-go ./cmd/ldap-go

./bin/ldap-go import \
  -db ./data/ldap-go.db \
  -ldif ./examples/base.ldif \
  -replace

LDAP_GO_ROOT_PASSWORD='change-me' \
  ./bin/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen 127.0.0.1:1389 \
  -root-dn cn=admin,dc=example,dc=com
```

在另一个终端使用 OpenLDAP 客户端查询：

```sh
ldapsearch -x -H ldap://127.0.0.1:1389 \
  -D cn=admin,dc=example,dc=com -W \
  -b dc=example,dc=com '(objectClass=*)'
```

连接同一 LDAP 服务启动 Web 管理控制台：

```sh
./bin/ldap-go web-admin \
  -listen 127.0.0.1:8080 \
  -ldap-url ldap://127.0.0.1:1389
```

打开 `http://127.0.0.1:8080/`，使用 LDAP Bind DN 登录。LDAPI、连接
OpenLDAP、TLS/TLCP、备份、审计、健康检查和生产部署见
[运行指南](docs/operations.md)。

## 从 OpenLDAP 迁移

OpenLDAP 后端数据库文件属于具体实现，不能直接复制到 ldap-go。应使用
已停止服务或已停止应用写入并设为只读的源库进行导出，确保分别导出的数据库
属于同一个一致迁移集，再使用 `slapcat` LDIF 作为迁移格式：

```sh
slapcat -n 0 -l config.ldif
slapcat -n 1 -l data-1.ldif

./bin/ldap-go import -db ./data/ldap-go.db \
  -ldif ./config.ldif -replace
./bin/ldap-go import -db ./data/ldap-go.db \
  -ldif ./data-1.ldif -database 1 -replace
```

多数据库迁移、离线工具、校验行为和密码哈希策略见
[迁移与密码指南](docs/migration-and-passwords.md)。

如果仍使用旧版 `slapd.conf`，先通过纯 Go 转换器生成并校验配置，再导入目录数据：

```sh
CGO_ENABLED=0 go run ./cmd/slapdconf-convert \
  -f /path/to/slapd.conf -out ./config.ldif
```

支持的指令、严格失败规则和直接数据库输出方式见
[slapd.conf 转换](docs/slapdconf-conversion.md)。

## 开发与测试

运行常规本地检查：

```sh
go test ./...
make compat
```

运行完整的 OpenLDAP、race、fuzz 和 Web 管理端测试：

```sh
make full
```

`make full` 会构建固定版本的 OpenLDAP 2.6.13，执行前请阅读
[测试文档](docs/testing.md)。发布与升级检查见[发布文档](docs/release.md)。

## 文档

| 主题 | 文档 |
| --- | --- |
| 运行和生产运维 | [运行指南](docs/operations.md) |
| OpenLDAP 迁移与密码 | [迁移与密码](docs/migration-and-passwords.md) |
| 旧版 `slapd.conf` 转换 | [slapd.conf 转换](docs/slapdconf-conversion.md) |
| 纯 Go 构建与平台审计 | [纯 Go 构建](docs/pure-go-builds.md) |
| 当前实现细节 | [实现状态](docs/implementation-status.md) |
| 已支持和未支持的行为 | [兼容性矩阵](docs/compatibility.md) |
| 常用生产功能范围 | [常用 OpenLDAP 生产功能](docs/common-production-scope.md) |
| 包结构和运行时设计 | [架构](docs/architecture.md) |
| 测试套件与 OpenLDAP 差异测试 | [测试](docs/testing.md) |
| OpenLDAP 100k 性能证据 | [100k 对比](docs/openldap-100k-evidence.md) |
| 生产规模和故障恢复测试 | [生产资格测试](docs/production-qualification.md) |
| 后端、Overlay 和模块边界 | [OpenLDAP 模块覆盖](docs/openldap-module-coverage.md) |
| Web 管理端功能边界 | [Web Admin 功能矩阵](docs/webadmin-feature-matrix.md) |
| 发布包和升级检查 | [发布](docs/release.md) |

## 许可证

见 [LICENSE](LICENSE)。
