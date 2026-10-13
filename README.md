# xcli

本仓库提供通用源码、测试和部署模板。文档中的文件路径与服务名是软件默认值，域名和 IP 为示例；不包含任何生产站点配置、用户数据、密钥或实际上线记录。

自托管的 Xray 节点管理面板。C++20 后端负责用户、订阅、用量、二次验证和加密备份；官方 Xray-core 负责代理协议与数据转发。前端使用原生 HTML、CSS 和 JavaScript，不加载第三方资源。

当前版本为 1.2.0，已在 Ubuntu 26.04 ARM64、Xray-core v26.3.27 上验证。提供 REALITY / XTLS Vision 和 WebSocket / TLS 两个 VLESS 入口。`app.py` 是迁移前的兼容实现，保留用于测试与本机维护；在线管理服务使用 C++。

## 功能

| 功能 | 行为 |
| --- | --- |
| 用户与订阅 | 每位用户独立 UUID、订阅令牌、二维码、配额和到期时间；支持停用、删除、流量清零和凭据轮换 |
| 健康监测 | 每分钟通过两个真实公网入口验证 HTTPS 出口 IP 和 SOCKS5 UDP DNS；失败、未知及过期结果分别显示 |
| 历史趋势 | 保留最近 30 天的流量、探测成功率和 HTTPS / UDP 延迟，支持 1 小时、24 小时、7 天和 30 天范围 |
| 故障通知 | 通用 HTTPS JSON Webhook，覆盖入口探测、探测结果中断、核心管理接口及本地自动备份；支持恢复通知、重试、Bearer Token 和消息签名 |
| 设备活动 | 按用户及入口展示最近产生流量的时间与上传、下载速率；60 秒内有流量标记为近期活跃 |
| 二次验证 | 验证器 TOTP、动态码重放拒绝、10 条一次性恢复码、失败限速、会话撤销 |
| 自动备份 | 默认每 6 小时生成 AES-256-GCM 加密的 SQLite 一致性快照，保留最近 28 份；支持手动备份、下载和恢复 |
| 操作记录 | 记录管理行为；不记录代理访问网站、请求路径或通信内容 |

服务器自检覆盖“服务器自身 → 公网节点入口 → 互联网”的路径。它不能证明用户所在地的运营商、Wi-Fi 或客户端配置正常。`scripts/probe.py` 可在外部机器单独运行，不会自动安装到其他设备。

设备活动以用户凭据的流量变化为依据，不等于实时在线设备清单。多个设备共用一个用户时无法区分；需要逐台识别时，为每台设备建立独立用户。采样中断超过 30 秒显示未知，避免将旧数据视为在线状态。

## 使用面板

登录后在“用户管理”中创建用户，再点击“连接”获取订阅地址或二维码。配额使用十进制 GB，0 表示不限；到期时间留空表示不过期。订阅返回 Base64 编码的 VLESS URI 列表，并附带 `subscription-userinfo` 用量信息。

重命名或调整配额不会更改凭据。“重置凭据”同时替换 UUID 和订阅令牌，使旧节点与旧订阅失效。订阅地址、二维码和探测配置均包含访问凭据，应保存在私密位置。

### 历史趋势

打开“历史趋势”选择时间范围。1 小时、24 小时、7 天和 30 天视图分别按 1 分钟、5 分钟、30 分钟和 2 小时汇总；流量显示每档累计字节数，延迟显示该档内有结果的探测平均值。当前时间档可能尚未结束。

成功率为成功次数除以已知探测次数，失败计入分母，未知单独显示。缺少采样的时段留空，不补成零流量或成功。只发生过一次成功且其后都是未知时，已知探测成功率仍是 100%，应结合未知次数和最近结果判断当前状态。

升级时导入数据库中仍保留的旧流量采样；旧版本通常只保留 7 天，因此不会立即拥有完整的 30 天流量。探测历史从升级后开始积累。采样由服务器执行，不能据此推断其他地区或客户端的可用性。

### 配置故障通知

1. 准备一个能接收 JSON 的公网 HTTPS 接口，证书须受系统信任。企业微信、钉钉等机器人有各自的消息格式，通常需要接收服务转换。
2. 打开“故障通知”，填写 Webhook 地址和接收服务需要的 Bearer Token 或 HMAC 签名密钥，输入当前管理密码；已启用二次验证时同时填写动态码或恢复码，然后保存。
3. 点击“发送测试”，查看投递记录，并在接收服务确认实际收到消息。“已投递”只表示接收端返回了 HTTP 2xx；平台是否最终展示消息需在接收端确认。
4. 勾选“启用故障与恢复通知”并保存。未勾选时仍可测试已保存的地址。升级不会预设地址或自动启用通知。

入口默认连续 3 个独立探测结果失败时通知，连续 2 个成功结果后通知恢复；重复读取同一份报告不会累计失败。探测结果中断和核心管理接口按分钟判断。未知结果不会把已有入口故障标记为恢复。本地自动备份出现错误或超过应执行时间 15 分钟时通知，恢复后再通知一次。整机断电、网络完全中断或面板停止时，这个面板无法主动通知，需要另外部署外部监控。

通知队列写入数据库，重启后继续投递。首次投递失败后分别等待 30、120、600、1800、3600 秒重试，总共最多尝试 6 次。接收端应按事件编号去重，以处理“接收成功但响应丢失”等情况。同一故障不会按检查频率重复排队；发生恢复时取消尚未发送的旧故障通知。修改通知配置会取消旧配置下排队的消息，启用后的当前故障会重新排队；正在发送的请求可能完成。

地址、Token 和签名密钥使用服务器恢复密钥加密保存，读取配置只返回目标主机名和是否已配置凭据。输入框留空表示保留原值，清除操作使用相应复选框。请求不使用代理、不跟随重定向，并在 DNS 解析后拒绝内网、回环、链路本地和其他保留地址。

接收端使用以下约定：

| 字段或请求头 | 含义 |
| --- | --- |
| `schema`、`id` | 消息格式版本（当前为 1）及事件编号；重试使用同一编号和正文 |
| `site`、`service` | 站点域名及服务标识：`reality`、`websocket`、`probe`、`core`、`backup` 或 `test` |
| `event` | `fault`、`recovery` 或 `test` |
| `title`、`message` | 可供展示的中文说明，不包含用户凭据或代理访问记录 |
| `time`、`started`、`duration_seconds` | Unix 秒时间、故障起始时间及持续秒数 |
| `X-Xcli-Event-Id` | 与正文 `id` 相同 |
| `X-Xcli-Timestamp` | 本次发送的 Unix 秒时间，每次重试重新生成 |
| `X-Xcli-Signature` | 可选，`sha256=` 加上 HMAC-SHA256 十六进制摘要；签名内容为时间戳、英文句点和原始正文的连接，密钥为配置的签名密钥 |

接收端应对原始请求正文验签，使用恒定时间比较，检查发送时间容差并按事件编号去重。接口为 `GET /api/history?range=1h|24h|7d|30d`、`GET/PUT /api/notifications` 和 `POST /api/notifications/test`；均要求登录，修改及测试要求 Origin 和 CSRF 校验，修改配置还要求重新验证管理员身份。

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

本版本未提供自动异地备份。备份中的数据库包含加密的通知配置；在线“恢复用户配置”保留当前通知配置和历史记录，离线整库提取则包含快照时的全部数据。

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
  nlohmann-json3-dev libsqlite3-dev libssl-dev libcurl4-openssl-dev libqrencode-dev libpng-dev \
  libgrpc++-dev libprotobuf-dev protobuf-compiler protobuf-compiler-grpc
bash deploy/build-cpp.sh build
```

Xray gRPC 协议文件固定为 v26.3.27，许可证和上游 SHA-256 清单位于 `cpp/proto/`。构建不下载源代码或执行远程安装脚本。

HTTP 兼容性测试还需要 Python 的 pytest、FastAPI、Pydantic 和二维码依赖，以及 `zbarimg`。可在发行版环境中安装 `python3-pytest python3-fastapi python3-qrcode python3-pil zbar-tools`。核心集成测试需要已安装的官方 Xray 二进制。

```sh
XG_LEGACY_APP="$PWD/app.py" \
XG_TEST_BINARY="$PWD/build/xray-gateway-panel" \
  python3 -m pytest -q cpp/tests/test_http.py cpp/tests/test_features.py cpp/tests/test_operations.py \
  cpp/tests/test_core_integration.py

cmake -S cpp -B build-asan -G Ninja -DXG_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-asan -j2
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build-asan --output-on-failure
```

测试使用独立临时数据库及回环端口。覆盖旧凭据兼容、CSRF、配额和权限撤销、真实核心连接、RFC 6238 向量、动态码重放、恢复码复用、备份篡改、在线恢复和离线提取。`--offline` 只用于隔离测试，不应作为生产启动参数。

通知测试还覆盖独立采样计数、未知结果、故障恢复、持久队列、重试上限、敏感字段加密、历史保留和空缺区间。真实 HTTPS 投递测试需要 Linux 的网络及挂载命名空间、`iproute2` 和 OpenSSL 命令工具；测试在独立命名空间中运行，使用临时证书与接收服务，验证签名、认证、失败重试、拒绝重定向、DNS 回环目标和证书主机名不匹配：

```sh
sudo bash cpp/tests/run-webhook-tests.sh "$PWD" "$PWD/build/xray-gateway-panel"
```

## 升级已有部署

已运行 1.1.0、完成探测服务和二次验证支持配置的主机，使用 `deploy/upgrade-operations.sh` 升级到 1.2.0。先构建并通过测试，再选择未使用的版本目录和 root 备份目录：

```sh
sudo install -d -m755 /usr/local/lib/xray-gateway/releases/1.2.0
sudo install -m755 build/xray-gateway-panel \
  /usr/local/lib/xray-gateway/releases/1.2.0/xray-gateway-panel
sudo bash deploy/upgrade-operations.sh "$PWD" \
  /usr/local/lib/xray-gateway/releases/1.2.0/xray-gateway-panel \
  /root/xcli-operations-upgrade-new
```

脚本先保存一致性数据库快照、配置、恢复密钥与服务覆盖配置，检查现有核心身份无需增删，然后只切换管理面板二进制和静态页面。用户凭据、订阅、管理会话、二次验证和累计流量均进行前后校验，核心、探测进程和 Nginx 不重启。管理页面在面板重启时短暂不可用。脚本失败后自动回退；也可执行备份目录内的 `rollback.sh` 恢复前一个兼容版本。回退保留当前数据库，避免丢失升级后的用户变化和流量。回退到 1.1 后停止新增通知和历史采集。

尚未完成 1.1 功能配置的旧部署，先按以下流程准备探测服务和恢复密钥：

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
