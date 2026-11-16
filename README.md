# iota-tools

macOS IOTA 工具：版本化配置、单机常驻 Supervisor、独立 Speedtest 模拟、独立 R2 上传/下载路由。

**初版工程代码；未在真实 IOTA 更新、macOS LaunchAgent 或实际 R2 上传/下载中验收。不得直接覆盖现用项目。**

## 仓库功能

- `tah_control/`：用户 LaunchAgent、进程管理、更新宽限期、重启限制、私有 CA 和 Finder 启动。
- `speedtest/`：本地 HTTP Speedtest 服务与测速列表替换。它是模拟数据，不代表真实公网性能。
- `r2_client/upload.py`：仅处理 R2 UploadPart PUT；18585 最多五并发、满额等待、7890 备用路线、CONNECT 故障恢复探测。
- `r2_client/download.py`：只处理 R2 对象 GET；500 KiB/s、10 秒滚动窗口，慢请求最多接管一次，固定代理重新下载并校验已交付前缀；全局并发接管默认 8。
- `r2_client/addon.py`：独立注册上传和下载模块。下载中继仅在 mitmdump 进程内绑定随机 loopback 端口，不增加独立守护进程。
- `r2-relay` 是独立的现有仓库；这里不重复实现本地 18585 或 VPS 中继。

不含 `iota-observer`、原始 IOTA API/Bridge 日志、旧版 8898 并行 GET 中继、原有完整 watchdog、Shadow 实验功能。CA、key、签名 URL、私人日志不提交 Git。

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

[r2.download]
replacement_proxy = "http://127.0.0.1:7893"
max_concurrent_takeovers = 8
```

下载默认使用 500 KiB/s、10 秒滚动窗口；配置可覆盖阈值、窗口、替换代理和全局接管并发（1–64）。单个 GET 最多接管一次，接管名额满时立即放弃接管、不排队。修改配置后运行 `reload`，会先校验配置、再受控重启 Supervisor、IOTA 与代理（有短暂中断）；目前不支持无中断热更新。证书凭据和热钱包密钥不放在配置库中。

## R2 下载行为与安全边界

仅匹配 HTTPS `*.r2.cloudflarestorage.com` 对象 GET；Bucket 列表、管理 API、多 Range 和非 R2 请求保持原路线。初始请求不使用替换代理。慢速判断以请求发起时刻为起点，首个完整 10 秒窗口形成后，每秒检查最近 10 秒上游接收量；低于 5,120,000 bytes 即低于 500 KiB/s 时触发一次接管。

接管使用相同 URL 和端到端请求头（代理 hop-by-hop 头除外），不构造 Range。若已向客户端交付正文，替换响应必须具有相同强 ETag、状态、长度、Content-Range、Content-Encoding、Content-Type 和 Last-Modified，并重新读取/校验已交付前缀 SHA-256；通过后丢弃前缀，只发送剩余字节。验证失败时继续仍可用的原连接；不能继续则以不完整响应失败，绝不拼接不一致数据。若没有强 ETag 且已有正文交付，则不接管。

运行指标写入用户私有目录：`r2-download-status.json` 保存当前进程汇总，`r2-download-events.jsonl` 持久保存最近 100 个接管事件。事件区分接管前失败、切换成功、完整传输完成和切换后传输中断，并记录接管后交付字节数、耗时及平均速度；不记录签名 URL、认证头、Cookie、异常原始消息或正文。代理重启后状态计数归零，但事件历史保留。下载与 UploadPart 上传是独立模块、独立并发额度。

## 更新恢复与网络边界

Supervisor 的代理生命周期与 `open -W` 不再绑定。更新器自行启动的 IOTA 可能丢失代理/CA 环境；Supervisor 检测 PID 改变，经过宽限期再优雅退出相应 IOTA 进程，以 `open --env` 注入 `HTTP_PROXY`、`HTTPS_PROXY`、`SSL_CERT_FILE`、`REQUESTS_CA_BUNDLE` 等重新启动。**需要真实自动更新测试确认不会干扰安装阶段。**

R2 上传不重放分片正文，也不改写签名 URL。主代理繁忙只等待，连接故障才在新请求中回退；代理都不可用时默认返回 503，不隐式直连。普通非对象 GET 透传。

运行前请按 [验收清单](docs/ACCEPTANCE.md) 完成 Mac、证书及真实 R2 端到端测试。CI 只能验证单元测试，不等于上线验收。
