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

`sync_ww_clash.py` 将 `ww` 策略生成到当前订阅专属的 Script 扩展。节点、代理组、公网 DNS 和通用分流规则由订阅维护；本地脚本只保存内网直连规则、内网 DNS 和 fake-IP 排除项。它读取已生效的 `/etc/resolver`，继续由 dnsmasq 处理文档、邮件等域名的细粒度分流。

Clash Verge 在激活配置和更新当前订阅时重新执行脚本：先放入本地内网规则，再接上最新订阅规则，对完全相同的规则保留第一次出现。对于本地 IPv4 网段、域名和域名后缀规则，若订阅靠前的同动作规则已完整覆盖它，且中间没有不同动作、需要额外解析或无法判定的规则，则省略该本地规则。订阅更新后重新计算覆盖关系；覆盖消失或出现冲突时，本地规则自动恢复。IPv6 网段及无法证明等价的规则保留。DNS 策略、fake-IP 排除与路由规则承担不同职责，不做跨字段去重。明确的内网 DNS 域名放在通用 `geosite:cn` 之前，并启用 `direct-nameserver-follow-policy`；其他 DNS 字段继续继承订阅。

### 同步与激活

在仓库根目录执行，Python 环境需要 PyYAML，候选预检需要 Node.js：

```sh
python3 scripts/sync_ww_clash.py
# 使用本机 Mihomo -t -d <Clash 配置目录> -f private/ww-clash/candidate.yaml 检查候选
python3 scripts/sync_ww_clash.py --apply
```

生成阶段不改变正在使用的配置。`--apply` 在核对输入和候选均未变化后，备份并写入当前订阅的 Merge、Rules、Script 扩展；遇到共享扩展或非本工具生成的自定义脚本会停止，避免覆盖其他配置。候选从原始订阅构建，不从上一次运行配置累加。候选用于预检，Clash Verge 实际生成的配置仍须在激活后核验。

完成写入后：

1. 在 Clash Verge 的 Profiles 中点击 **Reactivate Profiles**。
2. 在 **System Proxy Setting** 中，将自定义绕过列表完整替换为生成的 `private/ww-clash/bypass.txt`。该文件已保留当前列表中不属于 ww 的项和原有公共基础项；不要再与旧列表追加合并，否则已删除条目会残留。保留 Proxy Guard，关闭 Always use Default Bypass。
3. 验证内网域名的系统解析、Clash 解析和实际 HTTPS 访问，并确认公网直连与代理访问正常。

日常更新现有订阅时，无需重新运行同步命令：Clash Verge 自动将已保存的内网增量应用到最新订阅。删除后重新导入的订阅有新的配置关联，需要重新同步。

### 修改或删除 ww 条目

修改 `ww`，或切换网络位置导致 resolver 变化后，先按既有流程运行 `ww`，再执行上述同步与激活步骤。生成器每次完整替换自己负责的脚本数据，不与上一版内网规则取并集。因此删除的域名、网段、DNS 指向和 fake-IP 排除项会从本地增量中移除；绕过列表也会重新生成并清理。三个策略数组可以为空，支持删除最后一个条目。

如果订阅本身也包含同一条规则，删除 ww 中的条目后，订阅规则仍然保留。系统绕过列表的公共基础项同理。工具不会修改 `.zprofile`、dnsmasq、原始订阅、服务器或其他设备，也不会监听文件变化或自动执行 `ww`。审计工具每次运行仍直接读取 ww 当前策略。

### 从旧版 Merge / Rules 迁移

旧版曾将内网策略写入 Merge 和 Rules。首次迁移时，通过 `--legacy-policy` 指定上次已应用的 `policy.json`，并使用不同的输出目录，保留旧记录：

```sh
python3 scripts/sync_ww_clash.py \
  --legacy-policy private/ww-clash/policy.json \
  --output private/ww-clash-v2
# 检查 private/ww-clash-v2/candidate.yaml 后应用
python3 scripts/sync_ww_clash.py --output private/ww-clash-v2 --apply
```

迁移会移除已记录的旧内网增量，以及与当前订阅完全相同的公网 DNS 和前置规则，保留其他自定义项。迁移完成后不再传 `--legacy-policy`；后续可以继续使用 `--output private/ww-clash-v2`。此次实际迁移后 Merge 为空，Rules 的 prepend、append、delete 均为空，内网增量集中在当前订阅的 Script 中。

回退时，从对应输出目录的 `backup-*` 恢复三个扩展文件，再 Reactivate Profiles；如果修改过系统代理绕过列表，也在界面恢复。候选配置与备份可能包含节点凭据，均保存在 Git 忽略的私有目录中。

相关测试：

```sh
python3 -m unittest discover -s deploy/tests -p test_sync_ww_clash.py -q
python3 -m unittest discover -s deploy/tests -p test_local_network_policy.py -q
python3 -m unittest discover -s deploy/tests -p test_routing_audit.py -q
```

测试包含订阅更新后的 DNS、节点和规则继承，规则顺序及去重，旧配置迁移，条目删除，空策略，自定义项保留，以及准备后输入发生变化时拒绝写入。
