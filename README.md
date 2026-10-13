# xcli

本仓库提供通用源码、测试和部署模板。文档中的文件路径与服务名是软件默认值，域名和 IP 为示例；不包含任何生产站点配置、用户数据、密钥或实际上线记录。

自托管的 Xray 节点管理面板。C++20 后端负责用户、订阅、用量、二次验证和加密备份；官方 Xray-core 负责代理协议与数据转发。前端使用原生 HTML、CSS 和 JavaScript，不加载第三方资源。

当前版本为 1.1.0，已在 Ubuntu 26.04 ARM64、Xray-core v26.3.27 上验证。提供 REALITY / XTLS Vision 和 WebSocket / TLS 两个 VLESS 入口。`app.py` 是迁移前的兼容实现，保留用于测试与本机维护；在线管理服务使用 C++。

## 功能

| 功能 | 行为 |
| --- | --- |
| 用户与订阅 | 每位用户独立 UUID、订阅令牌、二维码、配额和到期时间；支持停用、删除、流量清零和凭据轮换 |
| 健康监测 | 每分钟通过两个真实公网入口验证 HTTPS 出口 IP 和 SOCKS5 UDP DNS；失败、未知及过期结果分别显示 |
| 设备活动 | 按用户及入口展示最近产生流量的时间与上传、下载速率；60 秒内有流量标记为近期活跃 |
| 二次验证 | 验证器 TOTP、动态码重放拒绝、10 条一次性恢复码、失败限速、会话撤销 |
| 自动备份 | 默认每 6 小时生成 AES-256-GCM 加密的 SQLite 一致性快照，保留最近 28 份；支持手动备份、下载和恢复 |
| 操作记录 | 记录管理行为；不记录代理访问网站、请求路径或通信内容 |

服务器自检覆盖“服务器自身 → 公网节点入口 → 互联网”的路径。它不能证明用户所在地的运营商、Wi-Fi 或客户端配置正常。`scripts/probe.py` 可在外部机器单独运行，不会自动安装到其他设备。

设备活动以用户凭据的流量变化为依据，不等于实时在线设备清单。多个设备共用一个用户时无法区分；需要逐台识别时，为每台设备建立独立用户。采样中断超过 30 秒显示未知，避免将旧数据视为在线状态。

## 使用面板

登录后在“用户管理”中创建用户，再点击“连接”获取订阅地址或二维码。配额使用十进制 GB，0 表示不限；到期时间留空表示不过期。订阅返回 Base64 编码的 VLESS URI 列表，并附带 `subscription-userinfo` 用量信息。

重命名或调整配额不会更改凭据。“重置凭据”同时替换 UUID 和订阅令牌，使旧节点与旧订阅失效。订阅地址、二维码和探测配置均包含访问凭据，应保存在私密位置。

### 绑定二次验证

1. 打开“安全与备份”，输入当前管理密码，点击“生成绑定二维码”。
2. 使用验证器扫描二维码，或手动输入绑定密钥。
3. 填入验证器当前显示的 6 位动态码，点击“确认启用”。二维码 10 分钟内有效，且只能由发起绑定的会话确认。
4. 安全保存一次性显示的 10 条恢复码。启用后其他管理会话退出，当前会话保留。

登录时需要密码与动态码，也可使用一条未使用的恢复码。动态码采用 RFC 6238 的 SHA-1、30 秒周期及前后一个周期容差，并拒绝重复使用已接受的时间步。动态码刚使用后，敏感操作可能需要等待下一周期。修改密码、关闭二次验证和重新生成恢复码都要求重新验证。

升级不会自动绑定验证器，也不会替用户启用二次验证。必须由管理员完成扫码与动态码确认，避免启用管理员无法使用的凭据。验证器密钥在数据库内加密保存，恢复码仅保存摘要。

### 备份与恢复

启动后首次生成自动备份，此后默认每 6 小时执行。失败会保留错误状态，5 分钟后重试。备份文件权限为 600，目录权限为 700，默认路径为 `/var/lib/xray-gateway/backups/`。

加密文件包含数据库与应用的服务器配置。恢复密钥位于 `/etc/xray-gateway/security.key`，应与备份文件分开妥善保管，并保留离机副本。备份不包含操作系统、Nginx 配置或 TLS 证书；它们需要单独保存。只保存在同一服务器的自动备份不能应对整机丢失。

面板恢复前会展示备份信息，要求输入备份编号、当前密码和已启用的二次验证码，并先生成恢复前快照。在线恢复只允许服务器配置匹配的备份，恢复用户、配额和订阅凭据，保留：

- 当前管理员密码、二次验证设置和恢复码使用状态。
- 每个恢复用户当前累计流量与备份累计流量中的较大值。
- 当前服务器配置、计数采样基线和管理操作记录。

恢复后所有管理会话失效；备份之后新增的用户会被移除，变更过的节点凭据按备份恢复。权限变更可能使节点短暂重连。系统不会因一次自检失败而自动恢复数据库。

离线解密演练使用一个不存在的新目录，不覆盖线上数据：

```sh
sudo /usr/local/lib/xray-gateway/panel-current \
  --extract-backup /path/to/backup.xgb \
  --secret-key /path/to/security.key \
  --destination /root/xcli-recovery-new
```

成功后得到 `gateway.sqlite`、`settings.json` 和 `security.key`，并已验证数据库完整性、清除旧登录会话。这个命令只提取文件，不切换运行中的服务。灾难恢复时先重新准备相同版本的核心、证书和服务，再停服务、安装提取文件并设置所有权，最后检查登录、订阅与真实节点连接。不得把同一备份未经检查地同时上线到多台服务器。

## 构建与测试

依赖来自 Ubuntu 软件仓库：

```sh
sudo apt-get install g++ cmake ninja-build pkg-config libcpp-httplib-dev \
  nlohmann-json3-dev libsqlite3-dev libssl-dev libqrencode-dev libpng-dev \
  libgrpc++-dev libprotobuf-dev protobuf-compiler protobuf-compiler-grpc
bash deploy/build-cpp.sh build
```

Xray gRPC 协议文件固定为 v26.3.27，许可证和上游 SHA-256 清单位于 `cpp/proto/`。构建不下载源代码或执行远程安装脚本。

HTTP 兼容性测试还需要 Python 的 pytest、FastAPI、Pydantic 和二维码依赖，以及 `zbarimg`。可在发行版环境中安装 `python3-pytest python3-fastapi python3-qrcode python3-pil zbar-tools`。核心集成测试需要已安装的官方 Xray 二进制。

```sh
XG_LEGACY_APP="$PWD/app.py" \
XG_TEST_BINARY="$PWD/build/xray-gateway-panel" \
  python3 -m pytest -q cpp/tests/test_http.py cpp/tests/test_features.py \
  cpp/tests/test_core_integration.py

cmake -S cpp -B build-asan -G Ninja -DXG_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-asan -j2
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build-asan --output-on-failure
```

测试使用独立临时数据库及回环端口。覆盖旧凭据兼容、CSRF、配额和权限撤销、真实核心连接、RFC 6238 向量、动态码重放、恢复码复用、备份篡改、在线恢复和离线提取。`--offline` 只用于隔离测试，不应作为生产启动参数。

## 升级已有部署

`deploy/upgrade-features.sh` 用于已有 `/etc/xray-gateway`、`/var/lib/xray-gateway` 和 C++ 管理服务的主机。先在普通用户目录构建并测试，然后将候选二进制安装到新的只读版本目录：

```sh
sudo install -d -m755 /usr/local/lib/xray-gateway/releases/1.1.0
sudo install -m755 build/xray-gateway-panel \
  /usr/local/lib/xray-gateway/releases/1.1.0/xray-gateway-panel
sudo bash deploy/upgrade-features.sh "$PWD" \
  /usr/local/lib/xray-gateway/releases/1.1.0/xray-gateway-panel \
  /root/xcli-upgrade-new
```

备份目录必须不存在。脚本保存数据库和配置基线，确认没有待撤销用户，再只切换管理面板。现有用户、订阅和服务器入口配置保持原值，探测账号通过 API 动态新增。Xray 和 Nginx 正常情况下不重启。管理页面在面板重启时会短暂不可用。

自检使用单独的 `xgprobe` 用户和 `xgmonitor` 共享组，仅能读取专用探测配置与写入探测结果，不修改代理进程阻止云内网和元数据访问的防火墙规则。专用探测凭据不会计入普通用户的配额或活动状态。探测服务由 `xray-gateway-monitor.service` 管理。

升级目录内有回退脚本。回退保留当前用户数据库，二次验证已启用时拒绝切换到无法执行二次验证的旧后端。回退到旧控制器可能因移除探测身份而使核心重连一次。旧版 Python 后端与 1.0 后端不支持二次验证，不应在已启用二次验证时直接启动。

`deploy/bootstrap.sh`、`deploy/configure.py` 和相关网络脚本保留了最初部署示例，包含特定主机与域名的设置，不是通用安装器。不要对在线主机重新运行它们来更新版本，也不要覆盖已有站点配置。

## 外部探测工具

复制服务器 `/etc/xcli-monitor/monitor.json` 到受控的外部机器，权限设为 600，并准备官方 Xray 和 curl。仓库中的 `scripts/probe.example.json` 只提供字段示例；不能用未注册的随机 UUID直接探测。

```sh
chmod 600 /private/path/monitor.json
python3 scripts/probe.py \
  --config /private/path/monitor.json \
  --xray /path/to/xray --scope external --once
```

成功时返回 `status: healthy` 和两个入口的 HTTPS、UDP 延迟，退出码为 0；失败为非零退出码。去掉 `--once` 可持续探测，通过 `--output /existing/private/directory/report.json` 写入结果。输出不包含节点凭据或访问内容。

## 运行边界与维护

用户新增通常在一个 5 秒采样周期内通过 gRPC 加载。Xray 删除用户只能阻止新连接，因此停用、删除、凭据重置、到期或配额用尽时，需要重启核心来结束旧连接，再恢复其他有效用户；这会使其他设备短暂重连。

流量累计与原始计数基线在同一事务中提交。异常退出仍可能丢失最后一个采样周期的流量，配额也可能超过一个采样周期，因此这些统计不应用于精确计费。

管理面板仅监听回环地址，通过现有 Nginx HTTPS 入口访问。会话采用 HttpOnly、Secure、SameSite=Strict Cookie，修改请求检查 Origin 和 CSRF。Xray、面板、探测进程均使用普通用户和 systemd 限制。

```sh
sudo systemctl status xray-gateway-panel xray-gateway-core xray-gateway-monitor nginx
sudo journalctl -u xray-gateway-panel -u xray-gateway-monitor -n 50 --no-pager
```

忘记管理密码时，可通过本机 root 维护工具交互式重置：

```sh
sudo python3 /opt/xray-gateway/scripts/gatewayctl.py reset-password
```

如果验证器和所有恢复码均丢失，root 可执行同一工具的 `disable-mfa` 操作，输入明确确认短语后关闭二次验证并退出所有会话。此操作会记入管理日志，之后应重新绑定验证器。

密码、UUID、订阅令牌、私钥、数据库、备份及真实探测配置都不应提交到仓库。`.gitignore` 已排除常见运行数据；提交前仍须检查实际文件清单。
