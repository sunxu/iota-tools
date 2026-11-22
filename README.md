# iota-tools

macOS IOTA 工具：版本化配置、单机常驻 Supervisor、独立 Speedtest 模拟、独立 R2 上传/下载路由。

**初版工程代码；未在真实 IOTA 更新、macOS LaunchAgent 或实际 R2 上传/下载中验收。不得直接覆盖现用项目。**

## 仓库功能

- `tah_control/`：用户 LaunchAgent、进程管理、更新宽限期、重启限制、私有 CA 和 Finder 启动。
- `speedtest/`：本地 HTTP Speedtest 服务与测速列表替换。它是模拟数据，不代表真实公网性能。
- `r2_client/upload.py`：仅处理 R2 UploadPart PUT；18585 最多五并发、满额等待、7890 备用路线、CONNECT 故障恢复探测。
- `r2_client/download.py`：只处理 R2 对象 GET；响应大于 24 MiB 时直接接管（不占慢速接管名额），否则保留 500 KiB/s、10 秒滚动窗口的慢速接管；固定代理重新下载并校验已交付前缀，慢速接管并发默认 16。
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

## 仅重载 mitmdump（手动操作）

`reload-proxy` 不执行 Git 拉取、依赖安装或自动更新；由已运行的 Supervisor 仅重启其拥有的 mitmdump 子进程。IOTA、Supervisor、Speedtest 与 R2 Relay 不由这个命令操作。现有 `reload` 仍是 Supervisor 整体重载，含 IOTA 重启。

```sh
# 自行更新代码后再主动激活（命令本身不会更新）
.venv/bin/python -m tah_control.cli reload-proxy
# 繁忙时不等待；默认最多等待 120 秒，可用 --wait 300 自定义
.venv/bin/python -m tah_control.cli reload-proxy --wait 0
.venv/bin/python -m tah_control.cli status
```

执行时新配置和 Addon 通过预检后，Supervisor 检查 mitmdump 私有活动快照。存在正在处理的 HTTP、TCP、WebSocket 或非拦截 CONNECT 时等待或返回 `BUSY`；状态缺失/过期则拒绝重载。空闲后有一次复查，并使用原端口和现有 CA 启动新进程，校验新 PID、活动快照与 R2 下载 Relay 就绪。回执仅包含请求 ID、状态、旧新 PID、代码指纹及安全原因码；可能返回 `APPLIED`、`BUSY`、`PREFLIGHT_FAILED`、`FAILED`。失败不承诺旧代码自动回滚。

这是**尽力避免中断的受控重启，不是零中断的连接迁移**：在检查后的极短竞态窗口中可能进入新请求，空闲连接也可能短暂断开。mitmproxy 使用持久的私有 Addon 入口脚本，Git 文件变化不会主动激活导入模块；只有新进程启动后加载更新代码。现有配置、CA 文件不会由 `reload-proxy` 修改。

## 版本化配置

默认 `config/defaults.toml`；本机差异写 `~/.config/iota-tools/config.toml`，比如：

```toml
[speedtest]
mbps = 400

[r2.upload]
max_concurrency = 3

[r2.download]
replacement_proxy = "http://127.0.0.1:7893"
direct_takeover_threshold_mib = 24
max_concurrent_takeovers = 16
capture_requests = true
```

下载默认使用 500 KiB/s、10 秒滚动窗口；单次响应长度严格大于 24 MiB 时立即尝试直接接管，不占用慢速接管的 16 个默认并发名额。其他请求保留现有慢速检测与 70% 进度限制；慢速接管名额满时继续监测，名额恢复后可再次判断，不排队。单个 GET 最多发起一次实际接管尝试。配置可覆盖大小阈值、速度、窗口、替换代理和慢速接管并发（1–64）。本机配置优先于仓库默认值；若 `~/.config/iota-tools/config.toml` 已显式设置 `max_concurrent_takeovers = 8`，需将该项改为 `16` 才会应用新默认值。修改配置后运行 `reload` 会受控重启服务（存在短暂中断），并非无中断热更新。证书凭据和热钱包密钥不放在配置库中。

## R2 下载行为与安全边界

仅匹配 HTTPS `*.r2.cloudflarestorage.com` 对象 GET；Bucket 列表、管理 API、多 Range 和非 R2 请求保持原路线。初始请求不使用替换代理。慢速判断以请求发起时刻为起点，首个完整 10 秒窗口形成后，每秒检查最近 10 秒上游接收量；低于 5,120,000 bytes 即低于 500 KiB/s 时触发一次接管。

接管使用相同 URL 和端到端请求头（代理 hop-by-hop 头除外），不构造 Range。大文件直接接管发生在原始响应头返回、尚未交付正文时，需要校验替代响应状态、长度、Content-Range 等元数据及已有 ETag；不一致则保留原始连接。若已向客户端交付正文，替换响应必须具有相同强 ETag、状态、长度、Content-Range、Content-Encoding、Content-Type 和 Last-Modified，并重新读取/校验已交付前缀 SHA-256；通过后丢弃前缀，只发送剩余字节。验证失败时继续仍可用的原连接；不能继续则以不完整响应失败，绝不拼接不一致数据。若没有强 ETag 且已有正文交付，则不接管。

临时请求采集默认开启（`[r2.download] capture_requests = true`），只在下载 Relay 就绪且 R2 GET 符合入口条件时记录一次。私有 `r2-download-requests.jsonl` 保存完整签名 URL、原始有序请求头（含 Authorization/Cookie）及 replacement_proxy；主文件 10 MiB、轮转保留 `.1` 一份，权限目录 0700/文件 0600，不逐条 fsync，采集失败不影响下载。**这些记录相当于访问凭证**：只供本机受控诊断，不得上传、提交 Git、粘贴进对话或备份到公共位置。问题定位后设置 `capture_requests = false` 并手动安全清理两份日志；关闭采集不会自动删除旧文件。请求采集日志与以下普通诊断严格分离。

运行指标写入用户私有目录：`r2-download-status.json` 保存当前进程汇总，`r2-download-events.jsonl` 持久保存最近 1000 条下载事件。事件区分接管前失败、切换成功、完整传输完成和切换后传输中断，并记录接管后交付字节数、耗时及平均速度；不记录签名 URL、认证头、Cookie、异常原始消息或正文。代理重启后状态计数归零，但事件历史保留。下载与 UploadPart 上传是独立模块、独立并发额度。

## 更新恢复与网络边界

Supervisor 的代理生命周期与 `open -W` 不再绑定。更新器自行启动的 IOTA 可能丢失代理/CA 环境；Supervisor 检测 PID 改变，经过宽限期再优雅退出相应 IOTA 进程，以 `open --env` 注入 `HTTP_PROXY`、`HTTPS_PROXY`、`SSL_CERT_FILE`、`REQUESTS_CA_BUNDLE` 等重新启动。**需要真实自动更新测试确认不会干扰安装阶段。**

R2 上传不重放分片正文，也不改写签名 URL。主代理繁忙只等待，连接故障才在新请求中回退；代理都不可用时默认返回 503，不隐式直连。普通非对象 GET 透传。

运行前请按 [验收清单](docs/ACCEPTANCE.md) 完成 Mac、证书及真实 R2 端到端测试。CI 只能验证单元测试，不等于上线验收。
