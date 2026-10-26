# 接入 PayPal 官方 Sandbox

本功能把门户订单接入 PayPal Orders v2：后台创建 PayPal 订单，买家跳转到 PayPal Sandbox 确认付款，后台捕获并核对付款，再调用现有 C++ 控制器开户或续期。网页返回地址不作为付款凭证。

当前只支持 Sandbox、USD 和单次购买/续期，不包含自动周期扣款、正式收款、退款或拒付后的自动权限调整。默认关闭，需要商户应用凭据才能启用。现有本地模拟付款仍可单独使用。

## 准备测试账户和应用

1. 登录 [PayPal Developer Dashboard](https://developer.paypal.com/dashboard/)，在 **Sandbox** 环境的 **Apps & Credentials** 中创建 Merchant 应用，关联 Sandbox Business 商户账户。保存该应用的 Client ID 和 Client Secret。[官方入门说明](https://developer.paypal.com/api/get-started/)
2. 准备另一个 Sandbox Personal 买家账户，用它登录测试收银台。商户和买家须为不同账户，账户可在 **Testing Tools → Sandbox Accounts** 中查看或创建。[Sandbox 账户说明](https://developer.paypal.com/sandbox-testing/accounts)
3. 使用商户的 Sandbox 登录信息登录 [sandbox.paypal.com](https://www.sandbox.paypal.com/)，在 **Account Settings → Business information** 中找到 PayPal Merchant ID。它需要与应用关联的商户一致。[Merchant ID 位置](https://developer.paypal.com/platforms/checkout/save-payment-methods/onboarding/platform/)

Client Secret 只保存在本机受限文件中，不放入仓库、网页、聊天消息或命令行参数。买家密码仅在 PayPal Sandbox 收银台使用。

## 配置并启动本地环境

在仓库根目录创建独立配置目录。以下复制操作保留已经存在的配置文件：

```sh
umask 077
mkdir -p ../.private/paypal-sandbox
cp -n portal/sandbox/paypal.example.json ../.private/paypal-sandbox/paypal.conf.private
chmod 600 ../.private/paypal-sandbox/paypal.conf.private
```

用本机编辑器填写该 JSON 文件。字段含义如下：

| 配置键 | 取值 |
|---|---|
| `PORTAL_PAYPAL_ENABLED` | 填写完整后改为字符串 `"1"` |
| `PORTAL_PAYPAL_ENVIRONMENT` | 保持 `"sandbox"`；其他值会拒绝启动 |
| `PORTAL_PUBLIC_ORIGIN` | 本地访问用 `http://127.0.0.1:18098`；公网联调用自己的 HTTPS origin，不带路径或尾部斜杠 |
| `PORTAL_PAYPAL_CLIENT_ID` | Sandbox 应用 Client ID |
| `PORTAL_PAYPAL_CLIENT_SECRET` | 同一应用 Client Secret |
| `PORTAL_PAYPAL_MERCHANT_ID` | 应用所关联 Sandbox 商户的 Merchant ID |
| `PORTAL_PAYPAL_WEBHOOK_ID` | 首先可以留空；配置官方 webhook 后填写其 ID |

使用新的容器名及宿主机端口 `18098/18099`，避免占用原门户沙箱的 `18088`。下面以 macOS Apple Container 为例：

```sh
container build -f portal/sandbox/Containerfile -t xcli-paypal-sandbox:dev .
PAYPAL_CONFIG_DIR="$(cd ../.private/paypal-sandbox && pwd)"
container run -d --name xcli-paypal-sandbox --cpus 2 --memory 4G \
  --publish 127.0.0.1:18098:8088 \
  --publish 127.0.0.1:18099:8089 \
  --mount "type=bind,source=$PAYPAL_CONFIG_DIR,target=/run/xportal-private/host,readonly" \
  --env PORTAL_PAYPAL_CONFIG=/run/xportal-private/host/paypal.conf.private \
  xcli-paypal-sandbox:dev
```

Docker 使用相同参数，将 `container` 改为 `docker`、`--memory 4G` 改为 `--memory 4g`。如果 `portal/sandbox/wheels/` 已有目标架构的完整依赖缓存，可在构建时追加 `--build-arg PORTAL_PIP_NO_INDEX=true`。

启动器读取私有配置后，只向工作进程、通知进程和迁移进程传入商户凭据。网页进程只收到启用标志与公开 origin。配置文件须为 `0600` 或 `0400` 的普通文件；`.conf.private` 文件同时被 Git 和镜像构建上下文排除。

共享目录必须挂载到 `/run/xportal-private/host`。镜像内的父目录 `/run/xportal-private` 由 root 持有，权限为 `0700`，用容器自身文件系统阻止网页和网关用户访问。Apple Container 的共享文件在显示 `0600` 时仍可能被其他容器用户打开，因此不能只依赖宿主机文件权限；启动器还会切换到这两个用户实际尝试打开配置，若能够打开便拒绝启动。不要覆盖这个父目录的挂载或权限。

首次启动会建立独立测试数据库，应用 `0002_paypal_sandbox` 迁移并设置数据库权限。旧模拟订单与付款标识保留原值。要升级已有容器，应先停用其订单处理进程、备份测试数据，再由 schema owner 执行 `migrate` 和 `portal_setup`，最后启动新进程；不要向运行中的旧进程直接切换数据库 schema。

## 检查凭据并完成一笔测试付款

先执行不创建订单、不扣款的连通性检查：

```sh
container exec xcli-paypal-sandbox \
  /opt/portal-venv/bin/python /workspace/portal/sandbox/paypal_check.py
```

成功时输出 `PayPal Sandbox OAuth: OK`。未配置 webhook 时会说明后台查询仍可使用；配置后还会检查 webhook 是否属于当前应用、URL 是否匹配、是否订阅付款完成事件。Merchant ID 在实际订单创建后与 PayPal 返回的收款方再次核对。

1. 打开 `PORTAL_PUBLIC_ORIGIN` 对应的地址，注册门户测试账户。
2. 在“购买或续期”中选择 **PayPal 官方 Sandbox**，创建订单。价格与期限来自后台套餐快照，浏览器不能指定付款金额。
3. 页面出现 **前往 PayPal Sandbox 付款** 后，使用 Personal 买家账户登录并确认付款。
4. 返回订单页。后台查询到 `APPROVED` 后发起捕获；只有独立查询确认 capture 为 `COMPLETED` 且金额、币种、收款方和订单标识匹配，才写入付款账本及开通任务。
5. 默认离线控制器最终显示 **沙箱权限已创建**。账户页应出现有效期和测试订阅地址。在商户 Sandbox 活动记录中核对同一笔付款，然后再创建一笔续期订单，确认有效期延长而订阅凭据保持一致。

订单页会自动刷新；关闭浏览器不影响后台查询。取消返回不会把订单标记为已付或抹掉已完成的付款。付款处理中不会提前开通。有效窗口结束后，后台不再主动发起新捕获，但仍核对已提交的付款；确认后的付款若遇到容量或网关状态问题，会保留账本并进入需要核对的状态。

## 接收官方 webhook

后台查询可以支持首次本地联调。要验证回调，需要一个可由 PayPal 访问的 HTTPS 入口。PayPal 向 HTTPS 443 端口投递 webhook；该地址必须对应同一个 Sandbox 应用。[官方 webhook 接入说明](https://developer.paypal.com/api/rest/webhooks/rest/)

将 `PORTAL_PUBLIC_ORIGIN` 改为自己的 HTTPS origin，重启本地测试容器，并从该 HTTPS 地址访问门户。反向代理只转发以下路径：

| 外部路径 | 本机目标 |
|---|---|
| `/webhooks/paypal/` | `127.0.0.1:18099/webhooks/paypal/` |
| 其他门户页面 | `127.0.0.1:18098` |
| `/webhooks/sandbox/` | 不对公网开放 |

在应用的 **Sandbox Webhooks** 中添加 `https://你的测试域名/webhooks/paypal/`，订阅 `PAYMENT.CAPTURE.COMPLETED`、`PAYMENT.CAPTURE.PENDING`、`PAYMENT.CAPTURE.DENIED`。把返回的 Webhook ID 写入私有配置，再重启通知及工作进程；上面的 `paypal_check.py` 可复查注册信息。

通知进程把原始事件字节、传输签名头和配置中的 Webhook ID 发送给 PayPal 的 `verify-webhook-signature` 接口。验证成功后，再查询对应订单及 capture。API 暂时不可用时返回 503，让 PayPal 重试。重复回调与后台查询会争用同一账户锁，付款唯一约束和持久化开通编号保证只生成一次开通结果。

PayPal 控制台的 **Webhook Simulator** 产生的是独立模拟事件，不能通过本项目使用的远程签名验证接口，也没有可核对的实际订单和 capture。验收应使用真实 Sandbox 买家付款产生的事件，不能把 Simulator 的投递成功当作付款链路通过。[官方说明](https://developer.paypal.com/api/rest/webhooks/rest/)

## 自动测试与边界

```sh
container run --rm --cpus 2 --memory 4G xcli-paypal-sandbox:dev test
```

测试不需要商户凭据。PayPal API 使用替身，覆盖创建或捕获超时、固定 `PayPal-Request-Id` 重试、付款处理中、拒绝付款、伪造返回、金额和收款方不匹配、重复及并发通知、网页数据库权限、旧数据迁移，以及真实 PostgreSQL/C++ 控制器的开通与崩溃恢复。请求编号和原始创建报文在调用 PayPal 前持久化；实现依据见 [Orders v2](https://developer.paypal.com/api/orders/v2) 和 [幂等请求说明](https://developer.paypal.com/api/rest/reference/idempotency/)。

完成自动测试只说明本地逻辑通过；OAuth 检查、买家付款、商户到账和真实 webhook 仍须使用自己的 Sandbox 应用验收。默认控制器处于离线模式，因此本测试不会验证真实代理节点可用性。

退款、拒付和撤销后的权限调整仍需人工处理，本实现不会自动退款或撤销已开通的权益。不要把 `sandbox` 改为 `live` 尝试正式收费；当前代码明确拒绝正式环境。
