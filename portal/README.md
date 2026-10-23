# 公众账户与支付沙箱

这个目录实现公众账户、订单、模拟付款和受限开通的第一条完整流程。它使用独立 PostgreSQL 数据库及 Unix 身份，通过本机 socket 调用现有 C++ 控制器。开发入口只允许 `PORTAL_SANDBOX=1`；其他模式启动失败。

当前使用本地模拟收银台。银行卡、PayPal、微信支付和支付宝选项用于覆盖相同订单流程，均未连接服务商的官方沙箱或真实商户。默认方案为 30 天、模拟金额 1.00 USD，不代表正式销售定价。浏览器不采集卡号、支付密码或真实支付账号。

## 启动与验证

需要本机 Linux 容器运行时。以下命令在仓库根目录执行，构建独立开发镜像，不使用现有服务器的配置、数据或凭据。构建上下文通过 `.dockerignore` 限定为源码和可选的依赖缓存；`private/` 不会发送到镜像构建器。

Python 依赖固定版本，并校验 PyPI 官方发布文件的 SHA-256。下载较慢时，可将匹配目标 Linux 架构的 wheel 缓存放入 `portal/sandbox/wheels/`；这些包不进入 Git，安装时仍校验哈希。缓存完整时，构建命令追加 `--build-arg PORTAL_PIP_NO_INDEX=true`，即可让 Python 依赖安装完全使用本地缓存。

使用 Docker：

```sh
docker build -f portal/sandbox/Containerfile -t xcli-portal-sandbox:dev .
docker run --name xcli-portal-sandbox --cpus 2 --memory 4g \
  -p 127.0.0.1:18088:8088 xcli-portal-sandbox:dev
```

macOS 的 Apple Container 使用相同镜像构建文件：

```sh
container build -f portal/sandbox/Containerfile -t xcli-portal-sandbox:dev .
container run --name xcli-portal-sandbox --cpus 2 --memory 4G \
  --publish 127.0.0.1:18088:8088 xcli-portal-sandbox:dev
```

网页入口为 [http://127.0.0.1:18088/](http://127.0.0.1:18088/)。创建测试账户后，依次点击“创建沙箱订单”“刷新状态”“模拟付款成功”，稍后刷新订单。成功状态为“沙箱权限已创建”，账户页可以查看有效期和测试订阅地址。

容器默认以 `--offline` 启动控制器，订阅使用 `sandbox.invalid` 和文档专用 IP。这个状态证明订单、收款记录和网关权限已一致提交，不表示已建立真实代理连接。程序另有 `active` 状态，只有逐个检查控制器管理的入口均存在对应用户后才会使用它。

完整自动测试使用新的临时 PostgreSQL 数据库和临时网关目录：

```sh
docker run --rm --cpus 2 --memory 4g xcli-portal-sandbox:dev test
```

正在运行的沙箱也可执行测试。Apple Container 将下面命令的 `docker` 替换为 `container`：

```sh
docker exec xcli-portal-sandbox /opt/portal-venv/bin/python /workspace/portal/sandbox/check.py
docker exec xcli-portal-sandbox /opt/portal-venv/bin/python /workspace/portal/sandbox/live_check.py
```

`live_check.py` 会创建全新的测试账户，完成四种模拟付款及三次续期，并检查实际 Unix 用户和 PostgreSQL 权限。它只输出验证结果；随机测试密码保存在容器内 root 私有文件中。重复执行会新增测试数据。

停止开发环境使用 `docker stop xcli-portal-sandbox` 或 `container stop xcli-portal-sandbox`。容器停止时保留其文件系统；本项目不会自动删除容器或测试数据。不要将初始化脚本直接运行在已有网关服务器上，也不要用原安装器部署本目录。

## 进程与权限

| 组件 | 沙箱 Unix 用户 | 数据与接口权限 |
|---|---|---|
| 网页 | `xportal_web` | 注册、会话、限流、购买意向、模拟付款意向；只读订单和本人的订阅展示 |
| 工作进程 | `xportal_worker` | 生成价格快照、预留容量、发送模拟支付通知、消费开通任务 |
| 支付通知接收器 | `xportal_worker`，独立 `hooks` 进程 | 只发布 `/webhooks/sandbox/`，校验签名与独立收款记录，写入支付账本和任务 |
| C++ 控制器 | `xgateway` | 网关 SQLite 的唯一业务写入者；创建和更新 portal 命名空间的代理用户 |
| 迁移与目录维护 | `xportal_owner` | 创建 schema、设置权限、维护测试套餐；不作为网页运行身份 |

网页进程没有支付签名密钥，不能连接开通 socket、读取网关数据库或更新支付/开通账本。网页数据库角色不能修改套餐价格、订单状态和权益版本，也不能插入已核验支付或开通任务。授权后的订单及订阅查询始终用当前登录账户过滤。

网页只向回环地址发布端口；支付通知监听在容器内部的 `127.0.0.1:8089`，控制器 HTTP 监听在内部的 `127.0.0.1:18080`。开通接口是 Unix socket，没有对应的 HTTP 路由。

## 订单与支付状态

1. 网页写入 `CheckoutRequest`。客户端传入的金额、币种或到期时间均不进入受信订单。
2. 工作进程锁定账户，从套餐表取价格与期限，向控制器预留名额，再生成 `Order`。同一账户不能同时开启第二笔待处理订单。
3. 网页只能提交 `SandboxPaymentRequest`。模拟收银台根据订单生成独立 `SandboxCharge`，工作进程发送带时间戳的 HMAC 回调。
4. 回调进程核对原始请求体签名、时间窗口、商户、订单、金额、币种、成功状态和模拟收银台记录。事件、支付记录、权益版本和开通任务在同一个 PostgreSQL 事务内提交。
5. 工作进程携带固定 `operation_id` 调用 C++ 控制器。控制器在同一 SQLite 事务中提交账户映射、用户变化和请求结果。重复请求返回第一次结果；相同 ID 携带不同参数会被拒绝。
6. 网关提交后，即使工作进程退出或 PostgreSQL 事务回滚，重试仍读取同一结果，不重复开户或延长有效期。续期保留 UUID 和订阅令牌。

同一支付事件和交易号都有数据库唯一约束。多个回调通过账户行锁串行处理，支付分配版本与已经应用的版本分别记录，避免延迟回调和新订单争用同一个权益版本。

订单预留 30 分钟。超时前完成的模拟收款，即使通知延迟，仍进入账本与待开通队列；开通时预留已失效则重新获取容量。无法获取容量、账户被管理员停用或状态冲突时，保留付款记录并显示需要核对，不把付款抹掉。退款、拒付和真实支付对账属于后续服务商适配范围。

## 受限开通协议

接口默认关闭；同时设置 `--provision-socket` 和 `--provision-uid` 才启用。`--portal-limit` 默认 50，允许范围为 1～500。控制器拒绝 UID 0 作为工作进程身份。

socket 父目录须属于控制器且不允许组或其他用户写入。控制器需具备工作进程主组的附加组成员资格；推荐目录权限为 `2750`，socket 权限为 `0660`。连接建立后还必须通过 Linux `SO_PEERCRED` 的精确 UID 校验。沙箱启动脚本演示了这些身份与目录设置，不修改生产 systemd 服务。

请求为单行 JSON，最大 8192 字节。接口只支持：

| 操作 | 必要参数 | 作用 |
|---|---|---|
| `reserve` | `operation_id`、`account_id` | 预留新账户名额或续期窗口 |
| `grant` | 上述字段及 `reservation_id`、`version`、`term_seconds` | 新建本系统账户或按顺序续期 |
| `status` | `operation_id`、`account_id` | 查询对应 portal 账户、订阅和节点同步状态 |
| `release` | 上述字段及 `reservation_id` | 释放该账户的匹配预留 |

标识使用 32 位小写十六进制文本。调用方不能指定已有代理用户 ID、UUID、订阅令牌、路由、SQL、文件路径或命令；额外字段会被拒绝。现有管理员创建的用户不自动成为 portal 用户。管理员已停用或删除的 portal 用户不会被续期自动恢复。

总上限为 500 条未删除代理用户加有效新账户预留，管理员手动开户使用同一限制。portal 自身还有默认 50 个账户的限制。单次期限最多 366 天，累计预付期限最多到当前时间后两年。官网注册账户数量与代理用户数量分别计算。

请求队列和报文大小有上限，连接读写有超时。控制器仅清理自己拥有且已确认没有监听者的遗留 socket；不会删除其他文件或活动监听。幂等历史保存在 SQLite 中，控制器重启后继续有效。

## 旧管理与订阅兼容

新增可选配置 `admin_origin`，仅用于管理写请求的来源检查；不设置时继续使用原 `origin`。C++ 与保留的 Python 实现都支持该回退行为。它要求不含路径、查询参数或凭据的 HTTPS DNS 地址，例如 `https://admin.example.com`；默认端口 443 和端口前导零会被规范化，使配置与浏览器发送的 Origin 一致。

原 `origin`、`domain` 继续生成订阅、Shadowrocket 和节点地址。这个改动不改变既有 UUID、订阅令牌、流量、管理员密码或会话。测试从旧 schema 启动新控制器，检查旧会话、订阅内容、二维码及管理来源限制。

新增 portal 表采用 `CREATE TABLE IF NOT EXISTS`，不重建原有用户表。控制器中已有 portal 账户或有效预留时，在线“恢复用户备份”会拒绝执行：单独回退网关用户表会使支付账本、映射与幂等历史不一致。协调恢复需停用新订单与工作进程，同时核对 PostgreSQL 和 SQLite；现阶段没有自动协调恢复工具。

回退到旧控制器前，应先停止新注册/下单及工作进程，确认没有未处理支付或有效预留，再按独立的发布步骤回退程序。数据库中的 portal 记录不得随意删除。支付与订阅数据也不应写入普通应用日志。

## 验证覆盖与下一阶段

自动检查覆盖正常开户和续期、重复/并发回调、错误商户/金额/币种/状态、过期签名、他人订单访问、数据库权限、管理员容量与预留竞争、工作进程失败、控制器强制退出及遗留 socket 恢复。真实控制器集成测试在提交网关结果后主动中断订单事务，检查恢复后账户、凭据和到期时间没有重复变化。

浏览器表单采用 Django CSRF 校验和 `Referrer-Policy: same-origin`。同源表单保留必要来源，跨站导航不发送来源；`Origin: null` 和外部 Origin 继续被拒绝。不要用关闭 CSRF 或信任 `null` 来解决表单来源问题。[Django CSRF 说明](https://docs.djangoproject.com/en/5.2/ref/csrf/)

后续上线仍需完成真实商户及官方沙箱适配、邮箱验证/找回密码与验证码适配、CN 地域规则和机器人防护、独立管理入口及旧路径封闭、联合备份恢复、真实节点生命周期和容量压测。本目录没有执行生产部署、DNS 切换或真实收费。现有核心的到期/撤销可能触发全体连接重建，仍需在生产发布前单独验证并决定处理方式。
