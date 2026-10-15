# 按订阅指定业务出口

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

启用后，面板的小火箭二维码直接指向 `shadowrocket://config/add/https://<domain>/s/<token>/shadowrocket.conf`。该远程配置包含业务节点、固定策略组、规则和自己的 `update-url`；客户端一次更新即可同时获得新的业务节点与分流，不需要编辑规则或单独维护模块。导入页也提供一个安装/更新按钮。

远程配置通过 `include = default.conf` 继承手机已有的完整默认配置，必须保留该文件。它不增加 `FINAL`，不修改原有 DNS、Host、重写或解密设置。首次导入后使用该配置，并保持全局路由为「配置」。后续点击「更新配置」或再次扫码即可更新；可在「设置 → 配置」启用自动后台更新。iOS 后台调度不保证立即刷新，需要立即生效时使用手动更新入口。只刷新首页节点订阅不会更新远程配置。

节点采用包含用户标识的固定内部名称；`XCLI-CLAUDE`、`XCLI-GITHUB` 各只有一个成员，不引用首页 `PROXY`，也不使用自动测速或故障切换。出口缺失时生成 `REJECT`。Claude 使用 `udp=0`，在域名代理规则前加入 `AND,((DOMAIN-SUFFIX,...),(PROTOCOL,UDP)),REJECT`，同时设置 `udp-policy-not-supported-behaviour = REJECT`。此配置保留用户原有 DNS 行为，与 Clash 的专用 DNS 策略不同；不承诺 DNS 随业务组固定出口。

`/s/<token>/shadowrocket.json` 返回导入方式，`/s/<token>/shadowrocket.conf` 返回私有配置。两个接口都检查用户有效状态；未启用用户不能下载专属配置。模块或配置包含的个人节点凭据必须按订阅一样保密，不可发送到第三方转换服务。凭据轮换后旧地址失效，需要重新扫码导入。

切回原 `default.conf` 可撤销本次分流。验证应包含原配置继承、远程更新、客户端规则测试、实际连接日志，以及切换首页节点后固定业务出口不变。服务端测试不能替代手机验收。

语法依据：[Shadowrocket 配置与扩展配置文档](https://github.com/LOWERTOP/Shadowrocket/wiki)、[该项目配置示例](https://github.com/LOWERTOP/Shadowrocket/blob/main/lazy_group.conf)。以实际安装版本的解析和连接结果作为最终依据。
