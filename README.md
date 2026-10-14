# xcli

本仓库提供通用源码、测试和部署模板。文档中的文件路径与服务名是软件默认值，域名和 IP 为示例；不包含任何生产站点配置、用户数据、密钥或实际上线记录。

自托管的 Xray 节点管理面板。C++20 后端负责用户、订阅、用量、二次验证和加密备份；官方 Xray-core 负责代理协议与数据转发。前端使用原生 HTML、CSS 和 JavaScript，不加载第三方资源。

当前版本为 1.3.0，提供 REALITY / XTLS Vision、WebSocket / TLS 两个 VLESS 入口，以及 Hysteria 2 / QUIC 入口。`app.py` 是迁移前的兼容实现，保留用于测试与本机维护；在线管理服务使用 C++。

安装器固定使用官方 Xray-core **v26.10.10（上游预发布版本）**并校验文件 SHA-256。旧版 v26.3.27 在本项目的真实核心测试中出现 Hysteria 2 UDP 大报文损坏，新版通过了 64～4096 字节随机报文逐字节校验，以及三个入口、计费和权限撤销测试。升级脚本保留旧核心供回退。上游版本状态见 [v26.10.10 发布页](https://github.com/XTLS/Xray-core/releases/tag/v26.10.10)。

## 一键安装

准备一台**全新的 Ubuntu 24.04 或 26.04 服务器**，支持 AMD64 / ARM64。需要 root 或 sudo 权限、systemd、公网 IPv4，以及能访问 Ubuntu 软件源、GitHub 和 Let's Encrypt 的网络。建议至少 2 GB 内存并预留 4 GB 磁盘空间用于编译。

先把域名的 A 记录指向这台服务器的公网 IPv4；只保留该地址，移除 AAAA 记录，并关闭 CDN 代理。云安全组和上游防火墙须放行 TCP 80、443 及 UDP 443。Hysteria 2 使用 UDP 443，可以与 HTTPS 的 TCP 443 同时运行。随后在服务器终端执行：

```sh
curl -fsSL https://raw.githubusercontent.com/checkmode/xcli/main/install.sh | sudo bash
```

按提示填写面板域名、证书邮箱、公网 IPv4 并确认安装。**无需手动下载或克隆代码仓库**：脚本自动解析固定提交、下载源码包、安装依赖并编译 C++ 面板，再安装经过 SHA-256 校验的官方 Xray、Nginx、HTTPS 证书和探测服务。首次构建需要数分钟，耗时取决于服务器和网络。

安装完成后访问输出的 HTTPS 地址。管理员用户名为 `admin`；随机初始密码仅保存在服务器的 root 私有文件中，使用下面的命令查看：

```sh
sudo cat /root/xray-gateway-admin.txt
```

登录后创建用户即可获取订阅与二维码。二次验证和故障通知默认关闭，按需要在面板中配置。Let's Encrypt 证书由 `certbot.timer` 续期，续期成功后自动检查并重载 Nginx，同时更新 Hysteria 2 专用证书副本；Xray 在证书重载周期内（最长约 1 小时）读取新文件。

### 无人值守与预检查

将下例中的域名、邮箱和公网 IPv4 替换为自己的值；`--agree-tos` 表示同意 [Let's Encrypt 服务条款](https://letsencrypt.org/repository/)：

```sh
curl -fsSL https://raw.githubusercontent.com/checkmode/xcli/main/install.sh | sudo bash -s -- \
  --domain panel.example.com --email admin@example.com --public-ip 203.0.113.10 \
  --agree-tos --yes
```

`203.0.113.10` 仅用于文档示例，安装器会拒绝示例地址和内网地址。可先只检查环境、端口和 DNS；此模式不安装软件、不修改系统配置：

```sh
curl -fsSL https://raw.githubusercontent.com/checkmode/xcli/main/install.sh | sudo bash -s -- \
  --domain panel.example.com --public-ip 203.0.113.10 --check --yes
```

`--reality-sni` 可指定 REALITY 目标域名，默认 `www.bing.com`，不能与面板域名相同。需要使用已有证书时，传入 `--certificate /path/to/fullchain.pem --private-key /path/to/privkey.pem`，此时无需邮箱和服务条款参数。已有证书必须与域名匹配、私钥未加密且证书链受系统信任；安装器会复制到 `/etc/xray-gateway/tls/`，**不会自动续期这类证书**。更新该目录内的证书后，执行以下命令同步 Hysteria 2 证书并重载 Nginx：

```sh
sudo python3 /opt/xray-gateway/deploy/certificate.py \
  --certificate /etc/xray-gateway/tls/fullchain.pem --private-key /etc/xray-gateway/tls/privkey.pem
sudo nginx -t && sudo systemctl reload nginx
```

`--tune-network` 启用下文的可回退网络调优，`--no-tune-network` 保留已有参数。交互安装会询问，默认不启用；无人值守安装也默认不启用。查看全部选项可在命令末尾加 `-s -- --help`。

### 安装保护与失败处理

安装器专用于全新服务器。发现已有 xcli 数据、Nginx 配置、同名服务账号或占用端口时会停止，不覆盖现有部署。已有用户请按后面的“升级已有部署”操作，不要重新运行安装器。

安装结束会验证管理服务、受信任的 HTTPS、核心账号同步，以及三个入口的 HTTPS / UDP 自检。若管理服务正常但节点自检尚未通过，保留已安装服务并返回退出码 `2`，请登录查看健康监测；这不表示完整节点验证成功。

安装日志位于 `/root/xcli-install-时间/install.log`。中途失败会停用本次新增服务、撤销本次专属防火墙规则，保留凭据、数据库、证书和日志；已安装的系统软件包也会保留。该目录内的 `rollback.sh` 可手动停用本次安装。失败后先检查日志，不要删除配置后盲目重试；再次运行会拒绝覆盖保留的数据。

安装测试覆盖 Ubuntu 24.04 / 26.04 与 AMD64 / ARM64 的临时机器，使用受测试系统信任的临时证书；公网 Let's Encrypt 签发仍取决于实际域名解析、80 端口可达性及签发方限制。

## 功能

| 功能 | 行为 |
| --- | --- |
| 用户与订阅 | 每位用户独立 UUID、订阅令牌、二维码、配额和到期时间；支持停用、删除、流量清零和凭据轮换 |
| 小火箭导入 | 一次扫码打开手机引导页，依次导入节点、安装 DNS 模块和切换全局代理；保留其他默认设置，另提供独立模块二维码 |
| 健康监测 | 每分钟通过三个真实公网入口验证 HTTPS 出口 IP 和 SOCKS5 UDP DNS；失败、未知及过期结果分别显示 |
| 历史趋势 | 保留最近 30 天的流量、探测成功率和 HTTPS / UDP 延迟，支持 1 小时、24 小时、7 天和 30 天范围 |
| 故障通知 | 通用 HTTPS JSON Webhook，覆盖入口探测、探测结果中断、核心管理接口及本地自动备份；支持恢复通知、重试、Bearer Token 和消息签名 |
| 设备活动 | 按用户及入口展示最近产生流量的时间与上传、下载速率；60 秒内有流量标记为近期活跃 |
| 二次验证 | 验证器 TOTP、动态码重放拒绝、10 条一次性恢复码、失败限速、会话撤销 |
| 自动备份 | 默认每 6 小时生成 AES-256-GCM 加密的 SQLite 一致性快照，保留最近 28 份；支持手动备份、下载和恢复 |
| 操作记录 | 记录管理行为；不记录代理访问网站、请求路径或通信内容 |

服务器自检覆盖“服务器自身 → 公网节点入口 → 互联网”的路径。它不能证明用户所在地的运营商、Wi-Fi 或客户端配置正常。`scripts/probe.py` 可在外部机器单独运行，不会自动安装到其他设备。

设备活动以用户凭据的流量变化为依据，不等于实时在线设备清单。多个设备共用一个用户时无法区分；需要逐台识别时，为每台设备建立独立用户。采样中断超过 30 秒显示未知，避免将旧数据视为在线状态。

## 运行信息、入口状态与诊断

概览页每个采集周期显示服务器实际采样时间、面板构建版本、面板与系统运行时长、主机 CPU、内存、Swap 和数据目录所在文件系统的用量。CPU 按相邻两次 `/proc/stat` 的差值计算，首次采样显示未知；内存使用量按 `MemTotal - MemAvailable` 计算。磁盘同时显示普通用户可用空间，不将根用户预留空间算作可用。流量采样时间与运行信息采样时间分别显示，刷新网页不会改变服务器采样时间。

运行中的 Xray 版本来自已核对身份的 `/proc/<PID>/exe version`，并随进程代次重新读取。不会使用 `settings.json` 的版本字段或磁盘上的新二进制替代运行版本。系统可能禁止无特权面板读取带 capability 的核心进程镜像；此时进程身份仍可按现有服务 cgroup 校验，但版本显示未知并说明读取限制。未能确定源码提交的归档构建显示“构建提交未知”。

接入节点页分别展示三个证据来源：

- **配置文件摘要**：读取核心启动参数指向的单一配置文件当前内容，列出监听地址、端口、协议、传输、安全类型及必要的 REALITY / WebSocket / TLS 参数；不返回用户凭据、私钥或完整配置。显示文件路径、摘要和修改时间。文件在核心启动后修改时提示可能尚未生效；文件未修改也不能单独证明运行配置完全一致。无法读取、多文件或目录配置时显示未知。
- **进程监听状态**：按核心进程文件描述符中的 socket inode 匹配 Linux 端口表，避免将其他进程占用同一端口当作核心正常监听。无权确认套接字归属时显示未知。WebSocket 显示核心内部监听，公网 HTTPS 的 TLS 由前置服务处理。
- **公网入口自检**：显示各入口最近的 HTTPS / UDP 探测结果、采样时间、最近成功时间及失败原因。探测点仍为服务器自身，不能证明手机所在网络或 DNS 路径正常。读取到的 TLS 证书只检查文件有效期，不代表核心已加载该证书或证书链验证通过。

“运行诊断”区分核心进程、gRPC 管理接口、访问权限同步和公网入口探测。管理接口结果与进程代次关联，核心重启后不会沿用上一代进程的成功状态。运行采样超过 `max(30 秒, 3 × 采集周期)` 时标记过期，自检继续使用原有的 180 秒有效期。

诊断页提供本次面板运行期间最近 50 条状态变化，以及数据库中最近 20 条由控制器发起的核心重连原因。外部进程重启的具体原因仍需查看服务日志；诊断页不会推断重启原因，也不采集访问网站或原始访问日志。新接口 `/api/runtime` 与 `/api/diagnostics` 均要求管理员登录，只读操作不改变配置或重启服务。

## DNS 与小火箭默认配置

防止手机 DNS 从本地网络漏出，关键是客户端的解析路径和失败回退策略。代理服务器使用普通 DNS，并不等于手机发生 DNS 泄漏；服务器 DoH 保护的是服务器到解析器这一段，属于独立的可选设置。

在面板“用户管理 → 连接 → 小火箭”中，用 iPhone 系统相机扫描二维码。手机引导页按“导入节点 → 安装 DNS 模块 → 关闭兼容模式 → 使用首页所选节点”的顺序引导设置。导入操作需在小火箭中确认后返回引导页继续；兼容模式需手动关闭，最后将全局路由设为“代理”、选择节点并连接。整个过程只需扫码一次。网页无法读取小火箭的安装结果或兼容模式状态，请在“配置 → 模块”确认“Xcli DNS 随所选节点”已启用，并按下文检查兼容模式。

在小火箭“设置 → 代理”中关闭“兼容模式（Compatibility Mode）”；英文界面路径为 `Settings → Proxy → Compatibility Mode`。安装 DNS 模块不会自动修改此开关。如果 VPN 已连接，修改后需断开并重新连接，期间会短暂中断 VPN。保留其他设置；需要回退时，在同一路径恢复原开关状态并重连。停用 DNS 模块不会恢复兼容模式。

如果同一节点、同一全局代理模式在蜂窝网络下正常，在 Wi-Fi 下却检测到本地运营商 DNS，应检查此设置。应用说明兼容模式会阻止 Shadowrocket 成为默认路由；网页出口已走代理，不代表每个 DNS 查询都经过模块指定的解析路径。一次 Wi-Fi / Hysteria 2 实测中，关闭兼容模式并重连后，六轮扩展检测均只出现 Cloudflare，用户复测也恢复正常。这确认了该组合操作在此场景有效，但未单独区分关闭开关与重连刷新状态的影响，也不保证覆盖所有隧道外流量。

验证时保持 Wi-Fi、节点和全局代理模式不变，在 [DNS leak test](https://www.dnsleaktest.com/) 首页重新运行 `Extended test`。同时核对出口 IP 和解析器身份：使用本模块时应看到预期的 Cloudflare，不应出现本地运营商 DNS；仅凭国家名称不能判断是否泄漏。若仍异常，检查模块启用状态及实际 DNS 日志，不要把旧测试结果或服务器自检当作客户端验证。

已有节点时可直接选择连接窗口中的“DNS 模块”页签，扫码安装，或复制模块地址到小火箭“配置 → 模块 → ＋”。面板提供的 `/shadowrocket-dns.sgmodule` 根据本服务器设置生成，只覆盖下列五项参数及本服务器域名的 `[Host]` 映射；其他字段和规则保留。模块不含节点凭据、脚本或解密证书，停用模块即可撤销覆盖。

引导地址的片段部分包含该用户的订阅令牌，应按订阅凭据保管；重置凭据后旧地址失效。引导页检查订阅是否仍可用，不要求接收者登录管理面板，也不加载第三方资源。节点订阅、模块安装与路由切换分别使用小火箭已公开的 URL 方案，见 [Shadowrocket 使用手册](https://github.com/LOWERTOP/Shadowrocket/wiki#url-schemes)。

仓库另提供不含服务器映射的 [通用 DNS 模块](clients/shadowrocket-dns.sgmodule)，下载地址为 `https://raw.githubusercontent.com/checkmode/xcli/main/clients/shadowrocket-dns.sgmodule`。使用通用模块时，还需按下文处理节点域名的引导解析。

节点订阅本身只提供节点，不修改客户端 DNS 或分流策略。也可手动把首页“全局路由”设为“代理”，再在当前启用配置的 `[General]` 中修改下列字段。已有同名字段时替换原值；保留其他字段和全部规则，不要把这个片段作为完整配置导入：

```ini
dns-server = https://1.1.1.1/dns-query#proxy
fallback-dns-server = https://1.0.0.1/dns-query#proxy
dns-direct-system = false
hijack-dns = :53
udp-policy-not-supported-behaviour = REJECT
```

`#proxy` 表示默认选中的节点，而不是固定节点名称，见 [Shadowrocket 官方说明](https://t.me/ShadowrocketNews/874)。主、备用列表中均不要混入 `system` 或普通 DNS 地址。默认局域网和系统绕过设置仍然保留；这些隧道外的流量不属于上述覆盖范围。

为避免连接节点前对节点域名进行本地解析，可在模块的 `[Host]` 中为面板域名设置实际服务器公网 IP。或者将 WebSocket 和 Hysteria 2 节点的服务器地址改为服务器公网 IP，同时保留面板域名作为 TLS SNI；WebSocket 的 Host 和路径也保留原值，继续验证证书。REALITY 已使用公网 IP，其 SNI 保留原来的目标域名。服务器 IP 变化时需更新映射；订阅更新后需检查手动修改的节点地址是否被覆盖。

服务器可单独启用公网系统 DNS 的 DoH 转发。以下命令在已部署服务器的源码目录中执行，要求 `/etc/resolv.conf` 已使用 systemd-resolved 的本机 stub，且没有运行中的 DNSCrypt 服务；备份目录必须不存在：

```sh
sudo python3 deploy/doh.py apply /root/xcli-doh-new
```

脚本从发行版软件仓库安装 `dnscrypt-proxy`，建立只监听 `127.0.0.1:5053` 的独立服务，使用固定 IP 的 `1.1.1.1` 与 `1.0.0.1` DoH 上游并验证 TLS 证书。上游地址无需明文 DNS 引导，也不配置普通 DNS 回退。系统公网解析经过 `systemd-resolved → 本机转发服务 → HTTPS 443`，同时覆盖 Xray 调用系统解析器的路径；更具体的云内网域名规则继续使用原有链路 DNS。该选项不拦截应用显式指定的其他 DNS 服务器，现有 UDP DNS 健康探测仍测试 UDP 转发能力。

脚本先验证 DoH，再切换系统解析器，不重启代理入口、面板或 Nginx。失败会撤销新增解析配置；也可执行 `/root/xcli-doh-new/rollback.sh` 回退。回退保留已安装的软件包并停用新增服务，用户、订阅、代理配置和证书不变。此选项不由一键安装自动启用。隔离测试使用真实转发程序验证 HTTPS 解析、上游失败及证书名称错误，并检查是否尝试普通 DNS 回退：

```sh
sudo unshare --net python3 deploy/tests/verify_doh.py /usr/sbin/dnscrypt-proxy
```

## 使用面板

登录后在“用户管理”中创建用户，再点击“连接”获取订阅地址或二维码。配额使用十进制 GB，0 表示不限；到期时间留空表示不过期。订阅返回 Base64 编码的两个 VLESS URI 和一个 `hysteria2://` URI，并附带 `subscription-userinfo` 用量信息。三个入口共享同一用户的配额和到期限制；Hysteria 2 使用该用户 UUID 作为认证密码，轮换凭据时一并替换。旧的双入口配置仍可使用，只有启用 Hysteria 2 后才增加第三个节点。

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
| `site`、`service` | 站点域名及服务标识：`reality`、`websocket`、`hysteria2`、`probe`、`core`、`backup` 或 `test` |
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

Xray gRPC 协议文件以 v26.3.27 为基线，所用用户管理、统计及 Hysteria 2 账号消息已在 v26.10.10 上验证兼容；许可证和上游 SHA-256 清单位于 `cpp/proto/`。构建不下载源代码或执行远程安装脚本。

HTTP 兼容性测试还需要 Python 的 pytest、FastAPI、Pydantic 和二维码依赖，以及 `zbarimg`。可在发行版环境中安装 `python3-pytest python3-fastapi python3-qrcode python3-pil zbar-tools`。核心集成测试需要已安装的官方 Xray 二进制。

```sh
XG_LEGACY_APP="$PWD/app.py" \
XG_TEST_BINARY="$PWD/build/xray-gateway-panel" \
  python3 -m pytest -q cpp/tests/test_http.py cpp/tests/test_features.py cpp/tests/test_operations.py \
  cpp/tests/test_core_integration.py cpp/tests/test_runtime.py

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

### 一键更新已有 1.3.0 面板

已运行 1.3.0、四个服务正常的 Ubuntu 24.04 / 26.04 主机，可直接执行：

```sh
curl -fsSL https://raw.githubusercontent.com/checkmode/xcli/main/update.sh | sudo bash
```

脚本解析固定提交、下载源码、安装缺少的编译依赖，并以服务账号编译、运行 C++ 单元测试。候选版本通过数据库和核心账号预检查后，脚本保存一致性备份，更新管理程序和静态页面，只重启面板。更新期间管理页面短暂中断；现有用户、订阅、二次验证和累计流量保留，Xray、探测服务和 Nginx 不重启。脚本不会更新核心版本、证书、防火墙、系统 DNS 或网络参数。

无人值守时添加 `-s -- --yes`；添加 `-s -- --check` 只检查已有部署；`--ref` 可固定完整的 40 位提交。日志、配置快照、数据库备份及 `rollback.sh` 保存于输出的 `/root/xcli-update-XXXXXXXX` 目录。切换后验证失败会自动恢复旧面板；手动执行该目录的 `rollback.sh` 也可回退。回退保留当前数据库及更新后产生的流量，新增编译依赖保留。

更新结束会核对用户身份、密码、已有会话、二次验证、累计流量及三个后台服务的进程。随后登录面板，检查概览运行信息、接入节点状态和诊断页；权限不足或没有采样的数据应显示未知。此入口仅处理 1.3.0 内的面板更新，旧版部署先按下文完成版本迁移。

### 1.2.0 升级到 1.3.0

先放行目标服务器的 UDP 443，并按“构建与测试”准备已验证的 1.3.0 二进制。以下命令在已有 1.2.0 部署上执行；备份目录必须不存在：

```sh
sudo python3 deploy/upgrade-hysteria.py upgrade --source "$PWD" \
  --candidate "$PWD/build/xray-gateway-panel" --backup /root/xcli-hysteria-upgrade-new
```

脚本校验并安装固定版本核心，添加 Hysteria 2 入口，更新订阅、探测服务和本机专属防火墙规则。它保留现有用户、订阅令牌、REALITY 密钥、WebSocket 路径、二次验证及累计流量，并重启核心、面板和探测服务，已有连接会短暂重连。Nginx 无需重启。使用自备证书的部署需同时传入 `--certificate` 和 `--private-key`；此类证书继续由原有流程更新。

脚本先保存配置、旧核心和数据库一致性快照，切换失败会自动回退。也可执行 `/root/xcli-hysteria-upgrade-new/rollback.sh` 回退到 1.2.0；回退保留当前数据库，包括升级后新增用户和累计流量，第三个入口停止提供服务。升级成功后仍需检查三个入口的服务端和外部探测；脚本不会修改云安全组。客户端更新原订阅即可获取 Hysteria 2，客户端须支持该协议和所在网络的 UDP 443 通信。

### 较早版本的升级路径

以下历史脚本分别要求对应版本的源码及二进制。先完成 1.1、1.2 升级，再使用当前版本的 Hysteria 2 升级脚本。

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

成功时返回 `status: healthy` 和所有已启用入口的 HTTPS、UDP 延迟，退出码为 0；失败为非零退出码。探测配置包含 `hysteria2_port: 443` 时检查三个入口，旧配置仍检查两个。去掉 `--once` 可持续探测，通过 `--output /existing/private/directory/report.json` 写入结果。输出不包含节点凭据或访问内容。

## 可回退网络调优

TCP 使用 Linux 内核 BBR，Hysteria 2 使用 Xray 的 QUIC 用户态 BBR；`net.ipv4.tcp_congestion_control` 只控制 TCP。可选调优会把新建队列默认值设置为 `fq`，将 UDP 收发缓冲上限提高至至少 16 MiB，并为可完整恢复的简单 `pfifo_fast` / `fq_codel` 实际网卡队列切换为 `fq`。已有更大的缓冲上限和复杂队列结构保留；不修改 MTU 或 TCP 自动调节范围，也不替换内核。

已有部署可先查看当前设置，再带自动恢复计时器应用。确认 SSH 和三个节点正常后，在 120 秒内执行 `confirm`；超时会恢复原值：

```sh
sudo python3 /opt/xray-gateway/deploy/network.py status
sudo python3 /opt/xray-gateway/deploy/network.py apply --rollback-after 120
sudo python3 /opt/xray-gateway/deploy/network.py confirm
```

原参数和实际队列快照保存在 `/etc/xray-gateway/network-before.json`，重启后由专用 systemd 服务重新应用。随时可以运行 `sudo python3 /opt/xray-gateway/deploy/network.py restore` 恢复；工具会保留快照，并拒绝覆盖后来被外部修改的托管文件或复杂队列。若还要回退 1.3.0 升级，应先恢复网络参数，再执行升级回退脚本。调优改善的是拥塞控制与缓冲条件，实际速度仍需按客户端网络测量。

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
