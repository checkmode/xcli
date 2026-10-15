# Clash 分流日志审计

本工具把 Clash Verge 的连接日志整理为最小化观测数据，再通过 SSH 发送到 Oracle 分析。它只生成报告和待审批规则，不写服务端订阅、Clash 配置或 DNS 设置，也不安装定时任务。

## 手动运行

在项目目录运行：

```sh
python3 scripts/routing_audit_oracle.py
```

默认读取 macOS 的 `~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/logs/sidecar/*.log`。默认目标是 SSH 别名 `oracle`，实际地址 `161.153.70.208`，并关闭该别名中旧的 ProxyCommand。主机密钥严格校验，使用此前核验并保存在 `private/routing-audit/oracle-known-hosts` 的记录；此文件不提交到 Git。在其他机器上使用时，需要用 `--known-hosts` 指定经过核验的主机密钥文件。

可覆盖日志目录、输出目录、SSH 别名、服务器地址和 IP 查询上限：

```sh
python3 scripts/routing_audit_oracle.py --max-ips 320
python3 scripts/routing_audit_oracle.py --logs /path/to/logs --output /path/to/private-report --known-hosts /path/to/verified-known-hosts
```

需要本地和 Oracle 都有 Python 3.9+；本地还需 SSH/SCP。只使用 Python 标准库，不需要 root 或第三方 Python 包。必须已有可用的 Oracle SSH 登录。Oracle 需要能访问 GitHub、Cloudflare DNS、AliDNS 和 ipwho.is 的 HTTPS 接口。

## 数据与报告

采集前先静态读取本机 `~/.zprofile` 中 `ww` 的三个策略数组及 `/etc/resolver`，不执行 shell。公司域名、明确绕过的主机和网段优先匹配；这些观测只保存到本地 `local-policy-report.json`，不会上传 Oracle。找不到策略或无法解析时停止采集，不退化为上传全部目标。可用 `--zprofile` 指定来源。

其余公网目标仅提取目标域名或公网 IP、规则类型、DIRECT/PROXY/REJECT、事件次数和样本时间范围。原始日志、请求路径、订阅凭据、代理节点名称和本地来源地址不上传。DNS 查询会将目标域名发送给 Cloudflare 和 AliDNS；IP 归属查询仅将公网 IP 发送给 ipwho.is。

日志轮转可能删除旧文件；报告只能说明当前保留样本中的行为。事件数不是字节数，也不是独立网页访问数。每次重新汇总当前文件，不把重叠窗口的次数累加到上一轮。

输出保存在 `private/routing-audit/`，该目录已被 Git 忽略：

| 文件 | 用途 |
|---|---|
| `report.md` | 中文审计报告 |
| `report.json` | 每个目标的规则、DNS、CNAME、IP、ASN 和查询状态 |
| `proposal.json` | 等待用户确认的精确域名规则及配套 DNS 建议 |
| `local-policy-report.json` | 本机明确直连目标及日志动作，不上传 Oracle |
| `summary.json` | 分类统计与判断结果指纹 |
| `history/` | 每次手动运行的报告副本 |

Oracle 的分析结果和 IP 缓存保存在登录用户的 `~/.local/state/xcli-routing-audit/`。上传的临时脚本和观测数据在本次运行结束时清理；报告包含域名/IP，按私有数据管理。输出文件默认权限为 600，新建工作目录为 700。服务器用文件锁串行执行分析，避免并发覆盖缓存；本地历史报告不自动删除。

## 判断依据

1. 从 GitHub 获取 Loyalsoldier/clash-rules 的 `release` 分支提交号，再从同一个提交读取 `direct.txt`、`proxy.txt` 和 `gfw.txt`。报告记录提交号、下载时间和每份文件的 SHA-256。规则库不可用时标记失败，不伪造空库的成功结果。
2. Oracle 分别通过 Cloudflare 和 AliDNS 查询 A、AAAA 和返回的 CNAME。境外调用国内 DNS 仍不等同于中国本地解析，CDN 地址可能与客户端不同。
3. 使用 ipwho.is 的国家、ASN、组织和 ISP 数据补充证据。这是第三方地理定位/网络归属数据，不是网站业务主体证明。
4. 日志已经显示 DIRECT 的目标列为“已直连”。走代理且被国内库收录、没有代理库冲突的目标列为“待确认直连”，只建议精确 `DOMAIN` 规则，不自动扩大为整个主域名。国内库与代理库同时命中的目标单列“规则冲突”。
5. IP 位于中国不足以自动直连；只靠这个证据的目标列为“待核实归属”。查询失败、结果不足或冲突时保持当前分流。

默认分析最多 200 个目标，优先处理有代理记录的目标；未分析目标明确列出。默认每次查询最多 160 个未缓存 IP，按目标轮流分配，避免某个大型 CDN 用完预算。成功的 IP 查询缓存 24 小时；失败结果不会当作有效缓存。`--max-ips` 可设为 1–500。预算遗漏和 DNS/IP 查询失败均保留在报告中；查询覆盖不足时不能把部分结果当作完整归属。

## 审批与订阅更新

`proposal.json` 始终标记为 `awaiting_user_approval`。即使规则库证据明确，也不会自动发布。空候选列表意味着本轮没有符合建议条件的新规则，不表示所有网络问题都已排除。

用户确认具体域名后，再执行单独的订阅发布变更：检查候选与当时生产配置的差异、将确认的精确规则放在通用代理规则之前、同步国内 DNS 策略、验证订阅并刷新客户端。未经确认的候选和归属不确定项不进入生产配置。

当前工具没有发布命令，也没有改动订阅生成器。后续若要把已批准规则持久接入生成器，需要作为独立变更实施和验证；日志分析不应直接覆盖生产配置。

## 验证

```sh
python3 -m unittest discover -s deploy/tests -p test_routing_audit.py -q
```

测试覆盖日志数据最小化、私网目标过滤、纳秒时间戳、域名后缀边界、规则冲突、单靠地理定位不得产生直连规则、报告重复运行和输入校验。网络查询是否成功以每次报告中的证据状态为准。

## 将 ww 策略同步到当前 Mac 的 Clash 扩展

`sync_ww_clash.py` 使用 PyYAML，先生成候选，再备份并写入当前配置的 Merge 和 Rules 扩展；不修改订阅原文件、服务端订阅生成器、`.zprofile` 或 dnsmasq。它读取已生效的 `/etc/resolver`，保留 dnsmasq 对文档、邮件等域名的细粒度分流。

```sh
python3 scripts/sync_ww_clash.py
# 先使用 Mihomo -t 检查 private/ww-clash/candidate.yaml
python3 scripts/sync_ww_clash.py --apply
```

随后在 Clash Verge 的 Profiles 中点击 Reactivate Profiles。将 `private/ww-clash/bypass.txt` 的条目与原系统代理绕过项合并，保存到 System Proxy Setting 的自定义列表，保留 Proxy Guard。同步脚本不会直接覆盖应用内存中的系统代理设置。

DNS 策略必须把明确的公司域名放在通用 `geosite:cn` 之前，并启用 `direct-nameserver-follow-policy`。仅设置 DIRECT 不代表已经使用内网 DNS。同步后分别核验系统解析和 Clash 解析，再访问实际 HTTPS 服务。

公司网络位置改变时，先运行既有 `ww` 更新路由和 resolver，再重新生成并应用本机扩展；审计工具每次运行都会重新读取策略。工具不监听网络位置变化，也不自动执行 `ww`。

回退时，从 `private/ww-clash/backup-*` 恢复本次改动前的两个扩展文件，再 Reactivate Profiles；系统代理例外在界面恢复原设置。包含节点凭据的候选配置与备份均留在被 Git 忽略的私有目录，不应分享。
