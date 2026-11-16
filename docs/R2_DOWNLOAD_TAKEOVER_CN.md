# R2 GET 慢下载接管 V1

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
- 最近 10 秒字节数小于 5,120,000 bytes（500 KiB/s × 10 秒）时，尝试一次接管。
- 每 GET 最多一次接管；全局名额非阻塞获取，满额立即放弃、不排队。
- 全局并发上限从配置读取，默认 8。

## 接管安全

替换请求复用原始 URL 和端到端请求头，不构造 Range；代理 hop-by-hop 请求头不会转发。

未向 IOTA 交付正文时，可以直接采用替换响应头和正文。已经交付正文时，必须满足：
- 状态码相同；
- 两边有相同强 ETag；
- Content-Length、Content-Range、Content-Encoding、Content-Type、Last-Modified 相同；
- 替换响应从头重新读取已交付字节数，并与原始已交付前缀 SHA-256 一致。

通过后丢弃替换响应的前缀，只继续发送未交付的字节。失败时不拼接；原连接仍可用则继续原连接，否则结束为不完整响应。无强 ETag 的已开始响应不做中途接管。

## 运维和隐私

- 内部 relay 仅绑定 127.0.0.1 的动态端口，不增加独立 Supervisor 子进程。
- 全局接管并发名额在新代理连接、前缀验证及剩余正文传输期间占用；完成、失败、取消均释放。
- `r2-download-status.json` 记录当前代理进程的计数、最后事件和事件历史文件名；进程重启后计数归零。
- `r2-download-events.jsonl` 独立追加事件，最多保留最近 100 个事件；目录权限为 0700，文件权限为 0600，代理重启后历史保留。
- `takeover_succeeded` 表示替代响应通过校验并完成切换；`takeover_completed` 才表示替代响应正文已完整交付。
- 事件记录接管阶段、异常类型、替代响应建立耗时、前缀校验耗时/字节数，以及接管后交付字节数、耗时和平均 KiB/s。
- `takeover_failed` 表示切换前失败；`takeover_stream_failed` 表示切换成功后传输中断；客户端取消单独记为 `takeover_stream_cancelled`。
- 不记录原始 URL、签名查询参数、认证请求头、Cookie、异常原始消息或响应正文；失败原因只记录固定校验原因或异常类型。
- 真实 Mac / IOTA / R2 验收仍是发布前置条件。
