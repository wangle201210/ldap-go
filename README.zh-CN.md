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

最新对照：2026-09-29 第二轮，100,000 个用户，基线 `b55f670` 与本轮冻结的
`current` 服务端，Apple M1 Pro，Go 1.26.4、`CGO_ENABLED=0`，OpenLDAP 2.6.13。
每行是三次批次耗时的中位数，逐请求轮换服务端，仅计 SDK 调用时间。
常用操作均配置 uid/member/objectClass 等值索引。相对性能为
`OpenLDAP / ldap-go × 100%`，100% 表示持平；使用频率是定性估计，不是流量统计。

| 常用功能 | 典型使用频率 | 次数 | ldap-go，默认权限 | OpenLDAP，默认权限 | 默认权限相对性能 | 显式 ACL 相对性能 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 用户 Bind，SSHA | 极高 | 1,000 | 89.35 ms | 70.77 ms | 79.2% | 79.1% |
| 非管理员 Base，热点用户 | 高 | 1,000 | 108.68 ms | 87.90 ms | 80.9% | 78.9% |
| 非管理员索引查询，热点用户 | 极高 | 1,000 | 118.26 ms | 93.65 ms | 79.2% | 77.7% |
| 直接所属组查询 | 高 | 100 | 17.19 ms | 12.11 ms | 70.4% | 67.9% |
| 读取千人成员组 | 中 | 100 | 99.85 ms | 90.09 ms | 90.2% | 92.6% |
| 嵌套组，客户端 BFS | 中～高 | 100 次遍历 | 54.73 ms | 40.87 ms | 74.7% | 72.9% |

相较基线 `b55f670`，常用非管理员 Base/等值查询中位数在默认权限下改善
2.9%～11.3%，显式 ACL 下改善 4.5%～5.4%。更广泛的原字面值管理员 DN 测量中，
分散用户等值查询**慢 14.5%**，不匹配 Compare **慢 10.0%**，并发 CLI 查询
**慢 57.7%**；固定夹具的 Add、Delete 分别**慢 3.9%、10.0%**。
独立并发复查的基线/当前中位数均为 338 ms，未在省去此前完整工作负载的条件下
复现该退化；执行顺序和预热历史不同，仍无法确定原退化的原因，全部样本保留。
独立的逐请求交错对照中，原字面值管理员 DN 的等值查询、不匹配 Compare
分别改善 9.6%、0.1%，但大写 DN 的等值查询慢 2.9%。该对照增加了不计时的
WhoAmI 检查，夹具活动及请求顺序也不同；原始串行退化结果保留，因果关系未确定。
[R2 报告](docs/common-ldap-performance.md)保留全部结果，包括独立的大写管理员
DN 测量表，以及读取、写入和 RSS 对照。共享主机测量不能确定耗时差异的原因。
**尚不能证明整体加速或与 OpenLDAP 持平，优化工作继续。**

R2 避免数据库值复制，并增加保守的根身份判断，保持快照、回调边界和授权行为。
组件比较与 SDK 结果分开，不新增分配剖析收益声明。Go 测试、vet 和 355 条
无跳过的原生检查通过；此前记录的操作属性缺口仍存在。

详见[证据索引](docs/evidence/performance-20260929-r2/README.md)、
[第一轮原文归档](docs/common-ldap-performance-20260929-r1.md)和
[SDK 对照工具](internal/cmd/ldapcommonbench/README.md)。

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
