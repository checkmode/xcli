# 应用安装、发布与回退

xcli 的应用版本由 `xcli-release` 管理。一个版本包包含 C++ 面板、静态页面、导入服务、监测服务、动态住宅池程序及本机管理工具。发布按“构建 → 上传 → 校验 → 切换 → 验证”执行；失败时恢复上一份程序，保留当前数据库、节点配置和累计流量。

新安装直接建立完整版本，已有 1.3.0 部署通过相同机制更新。候选程序需要修改数据库结构、核心账号或主机服务定义时，预检查会拒绝切换，应另行准备对应迁移方案。

## 目录归属

| 内容 | 路径 | 管理方式 |
| --- | --- | --- |
| 完整应用版本 | `/opt/xcli/releases/<版本编号>/` | 每次新增目录；不覆盖已有版本；清单记录每个文件的 SHA-256 |
| 当前与前一个版本 | `/opt/xcli/current`、`/opt/xcli/previous` | 由发布工具原子替换符号链接 |
| 发布工具本身 | `/usr/local/lib/xcli/release-tools/<工具摘要>/` | 独立版本目录；`tools-current` 选择当前工具 |
| 命令入口 | `/usr/local/sbin/xcli-release`、`xcli-layout`、`xcli-admin` | 管理应用版本和历史目录迁移 |
| 主机配套脚本 | `/usr/local/lib/xcli/host/` | 证书、网络参数、防火墙等；保留现有脚本的内容及文件摘要 |
| Xray 核心 | `/usr/local/lib/xray-gateway/xray` | 独立管理；面板发布不更换或重启核心 |
| 主机配置和密钥 | `/etc/xray-gateway/`、`/etc/xcli-monitor/`、`/etc/nginx/` | 保留现有路径和权限；不随应用版本切换 |
| 用户数据库和服务状态 | `/var/lib/xray-gateway/`、`/var/lib/xray-gateway-import/`、`/var/lib/xray-gateway-monitor/` | 持续写入的业务数据；代码回退时保持当前状态 |
| 发布事务 | `/var/lib/xcli/transaction.json` | 仅未完成的发布保留此文件；正常完成后移除 |
| 安装、更新构建日志 | `/var/backups/xcli/install/`、`/var/backups/xcli/updates/` | 每次操作独立目录；构建临时文件另存于缓存目录 |
| 初始管理员凭据 | `/etc/xray-gateway/initial-admin.txt` | 新安装仅 root 可读；旧部署接管时保留原凭据位置 |
| 发布快照与结果 | `/var/backups/xcli/releases/<时间-随机编号>/` | root 专用目录；一致性数据库备份、配置快照、事务记录 |
| 手动数据库备份 | `/var/backups/xcli/manual/` | `xcli-admin backup` 的默认输出位置 |
| 上传包、预检查副本 | `/var/cache/xcli/` | 发布包与可再生成工作文件；预检查副本在结束后自动清理 |
| 历史部署资料 | `/var/backups/xcli/legacy-<日期>/` | 原 home、root、临时目录和旧版本树；迁移清单保留原位置和 inode |
| 服务日志 | systemd journal | `journalctl -u xray-gateway-panel` 等；不在 home 下持续写构建或服务日志 |

`/opt/xray-gateway` 保留少量兼容链接，供原有维护入口、证书续期和服务引用使用；实际应用内容来自 `/opt/xcli/current`。`/usr/local/lib/xray-gateway/panel-current` 同样指向当前版本。它们不是第二份源码或第二套发布目录。

## 安装和一键更新

全新服务器运行根目录的 `install.sh`。安装器下载固定提交，调用共享构建器生成版本包，用发布管理器校验和安装完整版本，创建系统服务及配置后启动并验证。版本目录不保存用户数据、证书或主机脚本；不会再生成 `/root/xcli-install-*` 或旧式二进制目录。安装失败时，安装日志目录内的 `rollback.sh` 仅停用本次新增服务，保留配置、数据库与日志。

已有 1.3.0 部署运行 `update.sh`。源码更新和预构建包更新最终都由 `release.Manager` 执行 `stage`、候选预检查与 `activate`；旧布局自动先执行一次 `adopt`。以下命令的 `FULL_40_CHARACTER_COMMIT` 和 `PACKAGE_SHA256` 分别替换为实际提交和独立确认的包摘要：

```sh
sudo bash update.sh --check
sudo bash update.sh --ref FULL_40_CHARACTER_COMMIT --yes
sudo bash update.sh --bundle /absolute/path/xcli-release.tar.gz --sha256 PACKAGE_SHA256 --yes
sudo bash update.sh --rollback --yes
```

`--check` 不下载、不安装依赖、不切换程序。源码更新会安装缺少的构建依赖，完整包更新跳过本机构建；两者都保留当前 Xray、Nginx 和主机配置。`--rollback` 与 `xcli-release rollback` 是同一操作。`--check`、`--rollback` 不能与新包或源码提交选项混用。选定提交须包含统一发布工具，旧提交只能通过已封存的兼容版本回退。

## 手动接管已有部署

在目标服务器上安装已审阅的发布工具，然后接管正在运行的文件：

```sh
sudo bash deploy/install-release-tools.sh
sudo xcli-release adopt 20261017-baseline
sudo xcli-release status
sudo xcli-release check
```

`adopt` 从实际运行的二进制、实际生效的静态目录和已安装的配套程序建立基线，保留文件摘要；它不会把混合历史部署错误标记为某个干净 Git 提交。接管会保存配置与数据库快照，添加统一的服务启动覆盖配置，然后重启管理面板。Xray、Nginx、监测、导入服务和动态池保持原进程。

初次接管时 `previous` 为空。只有成功发布了第二个完整版本，才有可供普通回退的前一个版本。接管过程中失败会恢复原链接与服务覆盖配置；接管成功后，原 `/opt/xray-gateway` 保存在该次发布快照的 `legacy-app/` 中，原路径成为指向 `current` 和主机脚本目录的兼容链接；个人目录和旧构建资料按后文另行归档。

## 构建完整版本包

在已安装项目编译及测试依赖的 Linux 构建环境中，以普通构建账号执行。先把本次需要发布的修改形成 Git 提交，再固定完整的 40 位提交编号。工作区中尚未提交的修改不会进入包。

```sh
bash deploy/build-release.sh /path/to/xcli FULL_40_CHARACTER_COMMIT /path/to/output/xcli-release.tar.gz
```

`build-release.sh` 从该提交导出干净源码，调用安装器与更新器共用的 `build-source-release.sh`，创建新的编译目录并运行 C++ 和部署单元测试，再生成发布包和同名 `.sha256` 文件。源码摘要和二进制摘要必须与构建记录一致；重复使用缓存目录导致的旧版本标记不会被带入本流程。单独执行构建脚本不安装依赖或切换服务；一键安装和源码更新负责准备缺少的构建依赖。

工作流 `Build immutable application bundle` 在相关推送和拉取请求中构建被测试的固定提交，也可手动指定完整提交。它为 Ubuntu 24.04、26.04 的 x86_64、ARM64 共四种环境分别生成包和摘要，构建产物保留 30 天。工作流生成构建产物，不直接登录或发布到 Oracle。

包内 `manifest.json` 记录版本编号、提交、架构及组件 SHA-256，以及所需服务模板的摘要。新的 Git 构建包还记录 Ubuntu 版本；目标机拒绝系统版本或 CPU 架构不匹配的包，例如不能把 Ubuntu 26.04 的动态链接程序直接用于 24.04。包不包含用户数据库、节点凭据、证书或服务器配置。

## 准备、检查和发布

把包上传到 `/var/cache/xcli/incoming/`。该目录可由管理员提前创建，上传后将文件归属设为 root。以下 `PACKAGE_SHA256` 使用构建环境输出并经确认的完整摘要；`RELEASE_ID` 使用包的版本编号。

```sh
sudo xcli-release stage /var/cache/xcli/incoming/xcli-release.tar.gz --sha256 PACKAGE_SHA256
sudo xcli-release check RELEASE_ID
sudo xcli-release activate RELEASE_ID
sudo xcli-release status
```

`stage` 校验整个包的摘要，再检查每个文件、架构和必需组件；拒绝链接、路径穿越、重复项和同编号覆盖。准备版本包不会切换当前程序。

`check` 会核对 Git 构建包要求的服务模板与本机已安装的服务定义，定义不同时要求单独迁移。`check` 与节点导入共用 `/run/lock/xcli-update.lock`。存在未完成发布、正在检测或确认的节点操作、未完成导入事务时停止。候选程序以服务账号在数据库副本上执行预检查，检查数据库完整性、表结构和用户身份是否保持一致，以及核心是否需要增删账号。数据库副本在检查后删除，线上数据库不交给候选程序初始化。节点导入程序变化时，还会以服务账号比较新旧程序对现有路由的只读检查结果，拒绝丢失线上已有的路由兼容能力。

`activate` 再次执行预检查，保存一致性快照和原进程编号，随后停止需要切换的应用组件，切换 `current`，启动组件并验证：

- 面板实际进程确实来自目标版本。
- HTTP 健康检查、静态资源摘要及管理接口认证正常。
- 用户身份、管理认证信息、数据库结构和配置摘要保持一致，累计流量不倒退。
- Xray 和 Nginx 的进程编号保持不变；动态池代码未变时，其进程编号也保持不变。

面板在切换期间短暂不可用。导入、监测及动态池只有相应代码发生变化时才重启；动态池程序变化时，现有动态住宅连接可能重连。每次操作的结果和快照位置会显示在输出中。

## 回退与中断恢复

普通回退选择前一个已安装的完整版本，或明确指定某个兼容版本：

```sh
sudo xcli-release rollback
sudo xcli-release rollback RELEASE_ID
```

回退执行与发布相同的当前状态检查、快照和健康检查。它使用当前数据库和配置验证旧程序的兼容性，保留发布之后新增的用户、修改的配置和累计流量。成功后，刚退出的版本成为 `previous`，可再次发布。

切换后健康检查失败，工具会自动恢复原程序与配套组件。若进程被杀死、断电，或自动恢复没有完成，事务文件保留，后续发布被阻止。检查状态后执行：

```sh
sudo xcli-release recover
sudo xcli-release status
sudo xcli-release check
```

`recover` 依据持久化事务记录恢复发布前的程序位置并重启涉及的组件。恢复失败会继续保留事务及快照；不会把旧数据库覆盖到线上。恢复不是自动开机任务，断电后的异常状态需要管理员检查。

本机管理使用 `sudo xcli-admin backup` 等命令。入口禁用 Python 字节码缓存，备份不会向应用版本目录写入文件。

数据库灾难恢复、数据库结构升级、Xray 升级、节点配置回退、证书或网络策略调整是不同操作。发布快照为这些操作提供恢复材料，但 `rollback` 和 `recover` 不自动恢复业务数据。历史节点导入的恢复记录仍位于 `/var/lib/xray-gateway-import/backups/`，沿用对应配置操作的校验要求。

## 历史目录归档与位置恢复

归档前先生成计划，检查条目与服务引用：

```sh
sudo xcli-layout plan /var/backups/xcli/legacy-YYYYMMDD
sudo xcli-layout apply /var/backups/xcli/legacy-YYYYMMDD/manifest.json
```

计划仅选择已识别的项目文件，不处理 SSH、shell 配置等个人文件。执行前重新检查源路径 inode、目标是否为空及进程引用；迁移使用同一文件系统上的重命名，保存原权限、所有者和内容。系统自己的临时目录保持原状。

需要恢复文件原位置时：

```sh
sudo xcli-layout restore /var/backups/xcli/legacy-YYYYMMDD/manifest.json
```

此命令只恢复文件位置，不切换应用、不恢复数据库；若原位置已有新文件则停止，不覆盖。历史 `rollback.sh` 中可能含旧绝对路径和已经失效的配置前提，不能直接当作当前版本的一键回退命令。恢复历史资料位置后仍需逐项检查其适用性。

归档目前不自动删除。清理旧包和快照前，应保留当前版本、前一个版本、未完成事务引用的版本，以及需要追溯的历史基线。包含凭据的配置与数据库快照仅限 root 读取。

## 配置操作与历史迁移

`deploy/update-panel.sh` 是新更新器的兼容名称，已删除旧式逐文件覆盖代码。`bootstrap.sh`、`switch-cpp.sh`、`upgrade-features.sh`、`upgrade-operations.sh` 和 `upgrade-hysteria.py` 仅保留用于对应历史版本的一次性迁移，检测到 `/opt/xcli/current` 时拒绝运行。

住宅出口和动态池安装、扩容仍是配置操作，可能重启核心。它们在受管理的部署上使用当前版本的程序，要求相关程序与操作源码一致，并保持已封存的版本目录不变；配置回退也不恢复或删除版本包中的程序。此类新快照放在 `/var/backups/xcli/configuration/`，应用程序更新统一通过版本包进行。

## 验证范围

发布单元测试使用真实文件、SQLite 和隔离的系统服务适配层，覆盖首次安装、旧布局接管及失败恢复、同编号覆盖拒绝、包路径与摘要校验、系统版本不匹配、配置锁冲突、表结构变化、服务定义不一致、健康检查失败、断电恢复和管理工具写入隔离。

`Fresh server installation` 工作流在 Ubuntu 24.04 / 26.04 的 AMD64 / ARM64 临时服务器上运行真实安装、一键更新、回退和再次发布；独立任务从最后的旧 1.3.0 安装器建立旧布局、创建用户，再检查接管后的身份与配置保持情况。配置迁移测试检查住宅出口与动态池回退后版本包仍完整。构建工作流与安装工作流均不登录 Oracle，不自动替换其线上程序。

Oracle 在 2026-10-17 已完成线上基线接管、维护版本发布、回退和再次发布，历史资料共归档 189 项。当日核验保留了用户身份、认证信息、配置及累计流量，并通过外部 HTTPS 与订阅检查；这份历史记录不代替后续发布的实时检查。
