# 新技术栈开发目录

本目录与现有实现并行开发，不是可替换现网的完整版本。目标架构、迁移状态及香港上线条件见 [重构计划](../docs/rust-refactor.md)。

`rust/` 当前包含独立节点流量账本、授权响应校验、HTTPS 通道、状态机、Xray 控制适配器、实验性节点进程，以及旧版密码、TOTP、加密数据与登录会话的兼容代码；管理认证 HTTP 接入、安装、升级、迁移和生产验收尚未完成，不能替换现有服务。`web/` 包含 Node.js / TypeScript 接入层与 Vue / TypeScript 健康检查预览，不包含登录、用户或其他管理功能；不能作为生产面板部署。

以下命令在仓库根目录执行。账本测试需要 Rust stable、C 编译器和 Python 3；测试使用临时 SQLite 数据库。不得将测试驱动指向现有节点账本。

```sh
cargo test --locked --manifest-path rewrite/rust/Cargo.toml
cargo build --locked --manifest-path rewrite/rust/Cargo.toml --examples --bin xcli-node-service
XCLI_LEDGER_DRIVER="$PWD/rewrite/rust/target/debug/examples/ledger_driver" \
XCLI_PROTOCOL_DRIVER="$PWD/rewrite/rust/target/debug/examples/protocol_driver" \
  python3 -m unittest discover -s tests/rewrite -v
```

真实 Xray 适配器测试默认跳过。要在受控 Linux 环境运行，提供官方 Xray 的绝对路径；该测试新建临时配置、用户和环回监听，不应指向现有节点配置或管理端口：

```sh
XCLI_TEST_XRAY=/absolute/path/to/xray \
XCLI_XRAY_DRIVER="$PWD/rewrite/rust/target/debug/examples/xray_driver" \
  python3 -m unittest discover -s tests/rewrite -p test_xray_integration.py -v

XCLI_TEST_XRAY=/absolute/path/to/xray \
XCLI_NODE_SERVICE="$PWD/rewrite/rust/target/debug/xcli-node-service" \
  python3 -m unittest discover -s tests/rewrite -p test_node_service_integration.py -v
```

如需对照旧版 C++ 管理认证，还需 Python `cryptography` 和旧版面板二进制；测试自行生成临时数据库、密钥和凭据：

```sh
XCLI_LEGACY_PANEL=/absolute/path/to/xray-gateway-panel \
XCLI_AUTH_DRIVER="$PWD/rewrite/rust/target/debug/examples/auth_driver" \
  python3 -m unittest discover -s tests/rewrite -p test_panel_auth_compat.py -v
```

Web 工程需要 Node.js 24 或 26；Vue 的构建同时执行 TypeScript 类型检查。

```sh
cd rewrite/web
npm ci
npm run build
npm test
```

接入层默认监听 `127.0.0.1:18081`，将 API 和订阅请求转发到固定的 `127.0.0.1:18080`；端口可由 `XCLI_WEB_PORT` 和 `XCLI_CORE_PORT` 指定。运行 `npm start` 可检查预览；当前目录没有可供生产使用的 Rust 面板服务。请勿将测试服务接入生产 Nginx 或使用真实用户数据。
