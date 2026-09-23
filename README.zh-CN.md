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

最新 SDK 对照：2026-09-23，100,000 个用户，Apple M1 Pro，Go 构建关闭 cgo，
对照 OpenLDAP 2.6.13。每行是所列次数的总耗时中位数。Bind 和短查询使用
每种实现一个预热进程、交替请求的九批样本；扫描和写入使用三个独立进程。
写入在准备数据及缓存预热后测量。相对性能为 `OpenLDAP / ldap-go × 100%`，
大于 100% 表示 ldap-go 占优。

| 指标 | 次数 | ldap-go | OpenLDAP | 相对性能 |
| --- | ---: | ---: | ---: | ---: |
| 普通用户 Bind，SSHA | 3,000 | 360.74 ms | 200.82 ms | 55.7% |
| 管理员 Bind | 3,000 | 254.80 ms | 191.71 ms | 75.2% |
| Base 查询 | 3,000 | 287.94 ms | 239.10 ms | 83.0% |
| 索引等值查询 | 3,000 | 306.60 ms | 249.43 ms | 81.4% |
| Compare，匹配 | 3,000 | 302.24 ms | 199.92 ms | 66.1% |
| 前缀子串查询 | 20 | 1,112.34 ms | 621.19 ms | 55.8% |
| Add | 20 | 15.51 ms | 97.49 ms | 628.6% |
| Modify，修改非索引 description | 20 | 8.45 ms | 94.64 ms | 1,119.6% |
| ModifyDN | 20 | 27.36 ms | 89.73 ms | 328.0% |
| Delete | 20 | 18.35 ms | 88.51 ms | 482.5% |

完整普通属性导出一致。[最新报告](docs/performance-optimization-20260923-round11.md)
保留了首轮有回退的波动数据及交替复测：相对 `4a990fd`，交替复测中的普通
查询及 Compare 变化约在 1%，普通用户登录约快 3%，长 DN 的 Bind、Compare
约快 4%–6%。协议层分配降幅大于整机收益。首轮读/认证 RSS 为
414.9 / 95.4 MiB。小批量串行写入结果不能外推至所有生产负载。
启动、首次初始化、Bind、子串查询和内存仍有差距。
[写入索引报告](docs/performance-optimization-20260923-round8.md)记录初始化成本；
[历史分页结果](docs/openldap-100k-evidence.md)使用不同负载，单独保留。

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
