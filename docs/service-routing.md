# 按订阅指定业务出口

## 同时生成 Clash 与小火箭业务分组

`client_policies` 为指定用户启用统一分类：总代理入口、自动选择、故障转移、住宅国家分组，以及 AI、Telegram、YouTube、Netflix、国外媒体和其他流量。哔哩哔哩与 Apple 保留域名规则，直接指向 `DIRECT`，不生成独立策略组。两种格式共用同一份分类与节点关系，小火箭使用 `XCLI-` 名称前缀，避免覆盖用户原有分组。普通节点订阅继续提供相同的节点和凭据。

以下片段合并到现有 `settings.json`。用户 ID 应替换为实际值，并提前为同一用户保存完整的 `shadowrocket_base_profiles`。`ai_outbound` 引用现有出口标识，也可以设为 `proxy`，让 AI 默认跟随总代理：

```json
{
  "client_policies": {
    "00000000000000000000000000000000": {
      "ai_outbound": "residential-28"
    }
  }
}
```

启用时应将旧的 `CLAUDE` 业务策略合并到 AI，移除该用户旧的 `CLAUDE` 条目。若 `clash_service_routes` 已无其他策略，同时移除该用户的空条目和 `shadowrocket_service_users` 条目；新分类配置本身会启用小火箭远程配置。未启用 `client_policies` 的用户继续使用原来的导出行为。

| 分组 | 初始选择与用途 |
| --- | --- |
| PROXY | 默认故障转移；也可手选服务器协议或进入住宅节点 |
| 故障转移 | 按 REALITY、HTTPS、VMess TLS、Hysteria 2 顺序检测可用节点；省略未启用的协议 |
| 自动选择 | 对同一组服务器接入协议测速，按延迟选择；容差 100 ms |
| 住宅节点 | 先选国家，再选出口；同一固定出口的协议组初始使用 HTTPS |
| AI | Claude、ChatGPT/OpenAI、Gemini/NotebookLM、Copilot、Perplexity、Grok 共用一个选择；默认由 `ai_outbound` 指定，也可手选其他出口 |
| Telegram、YouTube、Netflix、国外媒体 | 默认跟随 PROXY，可单独选择国家或服务器协议 |
| 其他流量 | 未命中其他规则时使用，默认跟随 PROXY |

两个自动组仅检测服务器接入协议，不在不同住宅出口之间自动轮换；测试间隔均为 120 秒。测试 URL 可达只证明该检测请求成功，不证明 AI 或流媒体服务可用、账号地区正确或内容已解锁。已有客户端可能保留上次手选结果；刷新后应核对 PROXY 是否选中了预期策略。

AI 使用独立域名规则，不将整个 `google.com`、`github.com` 或共享 CDN 划入 AI。GitHub 网站继续走通用代理，Copilot 的专属接口归入 AI。国内 AI 服务保留原来的国内规则。AI 允许选择只支持 TCP 的住宅出口，因此其 UDP 请求明确拒绝，防止客户端跳过规则后走其他出口；依赖 UDP 的实时语音功能不在此配置的验证范围内。指定 AI 出口缺失时，默认项为 `REJECT`，不会自动改用其他出口；用户仍可显式改选。

Clash 的代理分类 DNS 跟随对应策略组；哔哩哔哩与 Apple 的 DNS 请求直接使用 `DIRECT`。小火箭保留完整基础配置的 DNS、Host、重写和 MITM 设置，增加分类规则，将原有规则中的通用 `PROXY` 目标接入 `XCLI-PROXY`，将 `FINAL,PROXY` 接入 `XCLI-其他流量`。小火箭 DNS 仍遵循原配置，不能据此声称与 Clash 的 DNS 出口完全一致。

每次修改节点、分类或规则，须成对检查以下三个资源：Clash 配置、小火箭节点订阅、小火箭远程配置。检查组内引用、AI 域名归属、私网优先级、故障组成员与出口缺失行为；保留原配置快照。客户端需分别刷新 Clash 订阅，以及小火箭的首页节点订阅和当前远程配置。服务端生成正确与客户端实际生效应分别记录；客户端由使用者操作时，不将其记为已验证。

上线只需更新订阅面板程序和配置，不需要更改代理核心、用户凭据或累计流量。回退到不支持 `client_policies` 的版本前，先恢复配套旧设置，再回退程序，避免旧版本拒绝新配置中的小火箭基础文件归属。

分类参考 [MetaCubeX 规则数据](https://github.com/MetaCubeX/meta-rules-dat)，Telegram 网段依据 [官方地址清单](https://core.telegram.org/resources/cidr.txt)。自动组行为参考 [Mihomo fallback](https://wiki.metacubex.one/config/proxy-groups/fallback/)、[url-test](https://wiki.metacubex.one/config/proxy-groups/url-test/) 和 [Shadowrocket 配置示例维护者文档](https://github.com/LOWERTOP/Shadowrocket/wiki)。

## 单独绑定业务出口

服务端通过 `settings.json` 中的 `clash_service_routes` 为指定用户生成业务分流。配置按用户内部 ID 关联，改名或轮换订阅凭据不会丢失策略。未配置的用户继续获得原来的节点、代理组、DNS 和规则。

此功能作用于 `/s/<token>/clash.yaml`。所有使用该用户 Clash 订阅的设备会在更新后收到策略；普通节点链接不携带分流规则。客户端需要支持内嵌规则集和逻辑规则的 Mihomo，并使用规则模式。已在 Clash Verge 的 Mihomo v1.19.32 上进行配置验证。

## 配置结构

以下是需要合并进服务端 `settings.json` 的片段，不是完整配置。将 `00000000000000000000000000000000` 替换为目标用户的内部 ID，保留其他用户和现有设置。

```json
{
  "clash_service_routes": {
    "00000000000000000000000000000000": [
      {
        "name": "CLAUDE",
        "outbound": "residential-28",
        "domains": [
          "claude.ai",
          "anthropic.com",
          "claude.com",
          "claudeusercontent.com",
          "claudemcpcontent.com"
        ],
        "udp": "reject"
      },
      {
        "name": "GITHUB",
        "outbound": "hysteria2",
        "domains": [
          "github.com",
          "githubusercontent.com",
          "githubassets.com",
          "github.io",
          "ghcr.io",
          "githubcopilot.com",
          "githubstatus.com"
        ],
        "udp": "proxy"
      }
    ]
  }
}
```

`outbound` 引用稳定的出口标识，不引用包含 IP 的显示名称。支持 `reality`、`websocket`、`hysteria2`、`vmess` 和 `residential-NN`。`hysteria2` 表示普通 Hysteria 2 节点；`residential-28` 即使使用 Hysteria2 接入，最终仍走该住宅出口。

每个业务对应一个只有一个成员的 `select` 策略组。它不包含 `PROXY`、自动选择或其他备用出口。出口不存在或被停用时，成员改为 `REJECT`，避免丢失出口后流量改走默认策略。住宅出口只支持 TCP，因此该类业务必须配置 `udp: reject`。非法名称、重叠域名、重复业务名称和非法出口标识会使预检失败。

域名按后缀匹配，包括根域名及其子域名。列表覆盖业务自有域名，不把共享 CDN、Google 登录或其他第三方服务的整个域名/IP 网段一并绑定。后续根据实际访问日志补充明确归属的域名。Claude 域名依据 [官方网络要求](https://code.claude.com/docs/en/network-config)，GitHub 域名可结合 [官方网络允许列表](https://docs.github.com/en/copilot/reference/copilot-allowlist-reference)维护。

## 生成与更新

服务端为目标订阅生成 `type: inline`、`behavior: domain` 的 `rule-providers`。例如 `service-CLAUDE` 只保存一份域名集合，路由按以下顺序引用：

```yaml
- AND,((RULE-SET,service-CLAUDE),(NETWORK,UDP)),REJECT
- RULE-SET,service-CLAUDE,CLAUDE
- RULE-SET,service-GITHUB,GITHUB
```

这些规则位于私网基础规则之后、通用 GeoSite 和 GeoIP 规则之前。明确拒绝 Claude UDP 可避免 TCP-only 节点不接收 UDP 时继续匹配后面的 `PROXY`。TCP 失败不会自动切换出口。普通 GitHub Hysteria 2 节点保留 UDP 能力。

业务域名的 `nameserver-policy` 使用经对应业务策略组发送的 HTTPS DNS，避免业务连接固定出口而解析继续随默认 `PROXY` 切换。代理服务器自身解析仍采用原有直接 DNS。

内嵌规则集随订阅一起更新，不独立轮询 HTTP 地址。服务端修改设置并重新加载管理服务后，客户端下次订阅更新便会得到新的域名集合和绑定；本地已缓存的旧订阅在更新前仍使用旧策略。若以后改为 HTTP rule-provider，可以独立更新域名集合，但代理组、出口引用和规则顺序改变仍需更新订阅。

本机 ww 扩展继续在订阅生成后注入内网策略，并按既有逻辑去重。它保留服务端的 rule-providers、业务代理组和公网 DNS；公司域名仍交给 dnsmasq。

## 上线与验证

部署新生成器前先构建并测试，保存旧二进制、设置、用户状态和其他用户的订阅快照。候选设置应通过新二进制的 `--preflight`，并确认没有新增或撤销核心账号，再替换管理服务与设置。此变更无需重启 Xray 核心或 Nginx。

更新目标客户端订阅后，验证：

- `CLAUDE` 只有指定住宅节点，`GITHUB` 只有普通 Hysteria 2；默认 `PROXY` 的选择保留。
- 通过客户端代理访问 Claude、API、GitHub 和资源域名，核对实际路由日志；网站的 HTTP 状态与出口是否正确分别记录。
- 通过 SOCKS UDP 发往 Claude 域名，确认命中 `REJECT`，没有落到默认出口。
- 校验出口缺失时生成 `REJECT`，以及隔离测试中指定节点不可用时不会回退。
- 检查其他用户的订阅内容、核心/Nginx 进程、用户凭据和流量计数未受影响。
- 再次访问内网、国内和其他海外目标，确认 ww 与原有分流保留。

这不是强制的服务器路由边界。应用流量必须进入 Clash；当前关闭 TUN 时，Git SSH 等连接需要应用自身的代理配置。已建立的连接也不会仅因更新订阅就重新选择出口。

回退时恢复部署前的设置和管理服务二进制，再让目标客户端更新订阅。不要回滚数据库或累计流量，也不要重置其他用户设置。

## Shadowrocket 专属远程配置

为已配置业务路由的用户显式启用 `shadowrocket_service_users`：

```json
{"shadowrocket_service_users": ["0123456789abcdef0123456789abcdef"]}
```

该列表默认为空；其中每个用户必须已有 `clash_service_routes` 策略。当前导出支持普通 Hysteria 2 和以 Hysteria 2 接入的住宅出口，复用同一份业务域名与出口配置。其他用户保持原导入流程；普通节点订阅和 Clash 订阅内容不变。

启用后，面板的小火箭二维码直接指向 `shadowrocket://config/add/https://<domain>/s/<token>/shadowrocket.conf`，导入页也提供安装/更新按钮。远程配置包含自己的 `update-url`；启用新配置后，点击「更新配置」或再次扫码即可更新规则与业务组。删除该文件或切回旧配置后，再次扫码仍属于首次导入路径，不能用已安装配置的更新结果代替验证。首次导入后使用该配置，并保持全局路由为「配置」。只刷新首页节点订阅不会更新远程配置。

需要保留手机完整配置时，将从手机导出的原文放入 `shadowrocket_base_profiles`，以同一用户 ID 为键。服务端保留原文中的 DNS、Host、重写、解密、已有节点/分组、规则及注释，只在规则前增加业务规则和订阅域名的 `DIRECT` 规则，在代理组段增加两个固定业务组，并设置更新地址。配置更新优先直连订阅域名，避开代理核心默认的自地址拦截。首次导入若仍使用旧配置，且未启用下述服务端 HTTPS 例外，应暂时断开小火箭后下载，启用新配置再恢复连接。

完整配置中的 `XCLI-CLAUDE`、`XCLI-GITHUB` 引用首页已有订阅中的精确节点名称，各只有一个成员，不引用首页 `PROXY`，也不使用自动测速或故障切换。当前绑定为指定住宅出口和普通 Hysteria 2。服务端出口不存在或停用时生成 `REJECT`；手机必须先刷新首页节点订阅，确保组内成员存在。手机本地缺失成员的行为不能仅凭服务端输出判断。修改用户名、节点名称或轮换节点凭据后，也需要刷新首页节点订阅。服务端不修改完整配置原有的 DNS 行为，不承诺 DNS 随业务组固定出口。

若要求在旧配置和代理连接均保持启用时完成首次下载，可为指定账号增加服务端 HTTPS 例外。`deploy/subscription_https.py` 仅生成待审核文件：在核心路由最前面增加一条同时限定账号、服务器公网 IPv4、TCP 和 443 端口的直连规则，并在现有出站防火墙的自地址拒绝规则前增加同一公网地址的 TCP 443 例外。原有内网、自地址其他端口和其他账号的核心拦截规则保留。该例外覆盖该公网 HTTPS 监听器，并不按 URL 路径过滤；它不绕过订阅令牌、面板登录或 TLS 验证。

生成工具不修改运行配置。应用前比较基线摘要、审查差异，使用 Xray 配置检查和 `deploy/tests/verify_subscription_https.py` 的独立实例测试验证目标账号、其他账号、私网和其他端口。生产应用需备份原核心与防火墙文件，单独插入运行中的防火墙规则，避免清空规则链；当前部署未开启路由热更新 API，因此核心规则生效需要重启核心，现有连接会重新建立。保留原数据库、节点身份和面板进程，等待账号重新同步，再验证手机在旧配置下扫码。失败时恢复两个原文件、删除新增防火墙规则并重启核心。

Claude 域名规则前插入 `AND,((DOMAIN-SUFFIX,...),(PROTOCOL,UDP)),REJECT`，以明确拒绝 UDP。原配置中的其他设置和规则顺序保留。为防止覆盖冲突，原文必须具有唯一的 `[General]` 与 `[Rule]` 段，最多一个 `[Proxy Group]` 段和更新地址，且不能已含 `XCLI-` 分组。完整配置注册表最多 16 个用户，总文本不超过 512 KiB。

未提供完整原文时，兼容原先的 `include = default.conf` 导出方式：远程配置内嵌业务节点凭据，并继承手机已有的默认文件，必须保留该文件。完整原文方式无需这个本地继承关系。可在「设置 → 配置」启用后台更新；iOS 后台调度不保证立即刷新，需要立即生效时使用手动更新入口。

`/s/<token>/shadowrocket.json` 返回导入方式，`/s/<token>/shadowrocket.conf` 返回私有配置。两个接口都检查用户有效状态；未启用用户不能下载专属配置。模块或配置包含的个人节点凭据必须按订阅一样保密，不可发送到第三方转换服务。凭据轮换后旧地址失效，需要重新扫码导入。

切回原 `default.conf` 可撤销本次分流。验证应包含完整原文保留、远程更新、客户端规则测试、实际连接日志，以及切换首页节点后固定业务出口不变。服务端测试不能替代手机验收。

语法依据：[Shadowrocket 配置与扩展配置文档](https://github.com/LOWERTOP/Shadowrocket/wiki)、[该项目配置示例](https://github.com/LOWERTOP/Shadowrocket/blob/main/lazy_group.conf)。以实际安装版本的解析和连接结果作为最终依据。
