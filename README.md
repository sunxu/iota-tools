# iota-tools

macOS IOTA 工具：版本化配置、单机常驻 Supervisor、独立 Speedtest 模拟、精简 R2 UploadPart 路由。

**初版工程代码；未在真实 IOTA 更新、macOS LaunchAgent 或实际 R2 上传中验收。不得直接覆盖现用项目。**

## 仓库功能

- `tah_control/`：用户 LaunchAgent、进程管理、更新宽限期、重启限制、私有 CA 和 Finder 启动。
- `speedtest/`：本地 HTTP Speedtest 服务与测速列表替换。它是模拟数据，不代表真实公网性能。
- `r2_client/`：仅处理 R2 UploadPart PUT；18585 最多五并发、满额等待、7890 备用路线、CONNECT 故障恢复探测。
- `r2-relay` 是独立的现有仓库；这里不重复实现本地 18585 或 VPS 中继。

不含 `iota-observer`、原始 IOTA API/Bridge 日志、R2 GET 8898 并行中继、原有完整 watchdog、Shadow 实验功能。CA、key、签名 URL、私人日志不提交 Git。

## Mac 首次部署

先关闭原有 IOTA 和旧 8899/8877 进程，固定本仓库路径，并确认 macOS 已登录 GUI 用户及 Python 3.11+。

```sh
./setup.command
./configure-hosts.command install
.venv/bin/python -m tah_control.cli check
.venv/bin/python -m tah_control.cli install
.venv/bin/python -m tah_control.cli finder
```

以后可从 Finder 双击 `~/Applications/IOTA Managed.app`。命令行：

```sh
.venv/bin/python -m tah_control.cli status
.venv/bin/python -m tah_control.cli start
.venv/bin/python -m tah_control.cli stop
.venv/bin/python -m tah_control.cli restart
.venv/bin/python -m tah_control.cli reload
.venv/bin/python -m tah_control.cli logs
.venv/bin/python -m tah_control.cli uninstall
./configure-hosts.command remove
```

安装用户 LaunchAgent 后默认自动启动；stop 会持久化停止意图，下一次登录也不重新启动 IOTA。uninstall 默认保留本机 CA、配置和 hosts；hosts 单独恢复。系统钥匙串和全局代理不会被自动修改。

## 版本化配置

默认 `config/defaults.toml`；本机差异写 `~/.config/iota-tools/config.toml`，比如：

```toml
[speedtest]
mbps = 400

[r2.upload]
max_concurrency = 3
```

严格校验配置 schema、字段和端口，拒绝非 loopback 的上游代理地址。修改配置后运行 `reload`，会先校验配置、再受控重启 Supervisor、IOTA 与代理（有短暂中断）；目前不支持无中断热更新。证书凭据和热钱包密钥不放在配置库中。

## 更新恢复与网络边界

Supervisor 的代理生命周期与 `open -W` 不再绑定。更新器自行启动的 IOTA 可能丢失代理/CA 环境；Supervisor 检测 PID 改变，经过宽限期再优雅退出相应 IOTA 进程，以 `open --env` 注入 `HTTP_PROXY`、`HTTPS_PROXY`、`SSL_CERT_FILE`、`REQUESTS_CA_BUNDLE` 等重新启动。**需要真实自动更新测试确认不会干扰安装阶段。**

R2 客户端绝不重放分片正文，也不改写签名 URL。主代理繁忙只等待，连接故障才在新请求中回退；代理都不可用时默认返回 503，不隐式直连。普通 GET 透传，移除的 Watchdog 及 8898 下载中继可能改变异常恢复与下载表现。

运行前请按 [验收清单](docs/ACCEPTANCE.md) 完成 Mac、证书及真实 R2 端到端测试。CI 只能验证单元测试，不等于上线验收。
