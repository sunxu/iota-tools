# R2 GET 下载接管（大小直接触发 + 慢速触发）

## 设计结论

mitmproxy 11.0.2 的响应流回调是同步函数。它适合对单个 chunk 做同步转换，不适合在回调内异步建立替换上游连接。V1 因此使用同一 mitmdump 进程内的 aiohttp loopback relay：

1. download addon 在 mitmdump 的异步 running hook 中启动随机端口的 loopback HTTP 服务。
2. requestheaders 保存原始 URL 和端到端请求头，然后把符合条件的 R2 GET 改写到 loopback relay。
3. responseheaders 对 relay 响应启用 mitmproxy 流式转发。
4. relay 自己通过 aiohttp 管理原始上游和替换代理上游，不阻塞 mitmproxy 主事件循环。
5. 上传和下载是独立 addon、独立文件、独立并发额度。

技术参考：
- mitmproxy v11.0.2 HTTP streaming: https://github.com/mitmproxy/mitmproxy/blob/v11.0.2/mitmproxy/proxy/layers/http/__init__.py
- mitmproxy v11.0.2 async addon hook dispatch: https://github.com/mitmproxy/mitmproxy/blob/v11.0.2/mitmproxy/addonmanager.py
- mitmproxy HTTP request host/authority setters: https://github.com/mitmproxy/mitmproxy/blob/v11.0.2/mitmproxy/http.py

## 固定规则

- 只识别 HTTPS `*.r2.cloudflarestorage.com` 对象 GET。
- 不接管 Bucket 列表、R2 管理 API、非 R2 GET、多 Range 或带正文的 GET。
- 初始上游不配置代理；替换上游使用 TOML 指定的 loopback HTTP proxy。
- 从请求进入 relay 开始计时，首个完整 10 秒窗口形成后，每秒检查最近 10 秒接收字节数。
- 原始响应头返回后，若符合对象 GET 的本次响应 Content-Length 严格大于 TOML 中的 `direct_takeover_threshold_mib`（默认 24 MiB），立即尝试大文件接管；不等待速度窗口，也不占慢速接管名额。206 按本次 Range 响应长度判断；大小未知走原有慢速检测。
- 其余 GET 最近 10 秒字节数小于 5,120,000 bytes（500 KiB/s × 10 秒）时，尝试慢速接管；从请求创建起的响应头等待阶段同样保留原有慢速判断。
- 每 GET 最多一次实际接管尝试；慢速并发名额满时继续原连接并在后续窗口重新检查，不排队；达到 70% 已交付进度时不再发起慢速接管。
- `max_concurrent_takeovers` 只限制慢速接管，默认 16；大文件直接接管不占该名额，但仍受 HTTP 客户端、代理和系统底层资源约束。
- 替代响应正文（包括中途接管的前缀校验）连续 30 秒无数据时，终止下载并释放名额，不回退原始连接。

## 接管安全

替换请求复用原始 URL 和端到端请求头，不构造 Range；代理 hop-by-hop 请求头不会转发。

未向 IOTA 交付正文、且原始响应头尚未到达的慢速接管，可以直接采用替换响应。大文件接管必须已有原始响应头，因此要先验证状态、Content-Length、Content-Range、Content-Encoding、Content-Type、Last-Modified 与已有 ETag 一致，不一致则保留原连接。已经交付正文时，必须满足：
- 状态码相同；
- 两边有相同强 ETag；
- Content-Length、Content-Range、Content-Encoding、Content-Type、Last-Modified 相同；
- 替换响应从头重新读取已交付字节数，并与原始已交付前缀 SHA-256 一致。

通过后丢弃替换响应的前缀，只继续发送未交付的字节。失败时不拼接；原连接仍可用则继续原连接，否则结束为不完整响应。无强 ETag 的已开始响应不做中途接管。

## 临时请求采集（默认开启）

- `[r2.download] capture_requests = true`：下载 Relay 已就绪且请求符合 R2 GET 入口规则时，`requestheaders` 每个下载入口只写入一次；与是否触发24 MiB接管或慢速接管无关。
- 独立私有 `r2-download-requests.jsonl` 记录 `schema=iota_r2_download_request_v1`、timestamp、request_id、method、完整原始 URL、按原始顺序保存的 Latin-1 可逆请求头二元数组，以及配置的 replacement_proxy。原始请求与替代请求仍复用同一个 context；普通事件仅通过 request_id 关联结果。
- 主文件严格不超过 10 MiB（包括每行结尾换行），超限时将旧主文件轮转至 `r2-download-requests.jsonl.1` 并覆盖旧 `.1`；单条大于上限直接跳过。目录权限 0700，两个文件 0600；仅进行追加写，不逐条 fsync，异常退出可能丢失末尾记录或出现不完整末行。
- 采集写入失败不影响 GET，控制台只发固定脱敏告警。普通事件、状态文件和控制台不包含请求 URL、Authorization、Cookie 等。
- **临时敏感凭证例外**：签名 URL 与 Authorization/Cookie 应视为有效访问凭证。定位结束后将 `capture_requests = false` 并人工清理主文件及 `.1`；关闭后历史文件不会自动删除，切勿提交、共享或公开备份。

## 运维和隐私

- 内部 relay 仅绑定 127.0.0.1 的动态端口，不增加独立 Supervisor 子进程。
- 慢速接管名额在新代理连接、前缀验证及剩余正文传输期间占用；大文件直接接管独立计数、不占慢速名额；完成、失败、取消均清理计数。状态分别提供 active_slow_takeovers、active_direct_takeovers 和 active_total_takeovers。
- `r2-download-status.json` 记录当前代理进程的计数、最后事件和事件历史文件名；进程重启后计数归零。
- `r2-download-events.jsonl` 独立追加事件，最多保留最近 1000 个事件；目录权限为 0700，文件权限为 0600，代理重启后历史保留。
- `takeover_succeeded` 表示替代响应通过校验并完成切换；`takeover_completed` 才表示替代响应正文已完整交付。
- 事件记录接管阶段、异常类型、替代响应建立耗时、前缀校验耗时/字节数，以及接管后交付字节数、耗时和平均 KiB/s。接管及下载汇总记录 trigger=file_size/slow_speed 与 capacity_bypassed；不含签名 URL。
- `takeover_failed` 表示切换前失败；`takeover_stream_failed` 表示切换成功后传输中断；客户端取消单独记为 `takeover_stream_cancelled`。
- 替代正文连续 30 秒无数据时记录 `takeover_stream_stalled` / `REPLACEMENT_STREAM_STALLED`：下游尚未收到响应头则返回 502；已开始响应则关闭连接，留下明确的不完整响应；两种情况都释放并发名额且不回退原始连接。
- 普通事件、状态和控制台不记录原始 URL、签名查询参数、认证请求头、Cookie、异常原始消息或响应正文；唯一例外是上述明确开启的独立私有请求采集文件。失败原因只记录固定校验原因或异常类型。
- 真实 Mac / IOTA / R2 验收仍是发布前置条件。
