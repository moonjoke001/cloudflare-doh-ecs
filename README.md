# Cloudflare DoH ECS

一个部署在 Cloudflare Workers 上的 DNS-over-HTTPS 服务，支持国内外域名分流、ECS 和上游故障回退。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Akiiia/cloudflare-doh-ecs)

## 相关链接

- [LINUX DO 社区发布帖](https://linux.do/t/topic/2665830)：项目介绍、部署教程与交流讨论。

## 功能

- 支持 RFC 8484 DoH GET 和 POST 请求
- 国内域名使用 AliDNS，失败后回退腾讯 DNSPod
- 其他域名使用 Google DNS，失败后回退 Cloudflare DNS
- ECS 按上游独立控制：默认仅发往 Cloudflare（CDN 就近），Google 等拿干净查询
- 主用慢时自动对冲备用（可配延迟），热点回答按 TTL 缓存
- 国内域名规则通过 Workers KV 和 Cron Trigger 自动更新
- 不记录完整查询域名和客户端 IP

## 部署

点击上方 **Deploy to Cloudflare** 按钮，授权 Cloudflare 访问 GitHub。系统会复制项目模板，并在你的 GitHub 账户下创建一个独立的部署仓库。
Cloudflare 会通过该仓库自动创建并部署 Worker、KV 命名空间以及每日规则更新任务。

部署完成后打开详情页-域-启用

DoH 地址：

```text
https://<你的 Worker 域名>/doh
```
首次查询会自动下载并初始化国内域名规则。

## 默认上游

| 分组 | 主上游 | 备用上游 |
|---|---|---|
| 国内域名 | AliDNS | 腾讯 DNSPod |
| 其他域名 | Google DNS | Cloudflare DNS |

主上游出现网络错误、超时、异常响应或 DNS `SERVFAIL` 时，才会尝试同组备用上游；不会在国内和国外分组之间回退。

## ECS 作用域

ECS（EDNS Client Subnet）告诉上游客户端所在网段，让 CDN 返回就近节点。默认策略：

| 上游 | ECS | 原因 |
|---|---|---|
| 国内 AliDNS / 腾讯 | 带 | 就近 + 结果本来就是按国内视角算的 |
| 国外 Google（主） | 不带 | 干净查询，不暴露客户端网段 |
| 国外 Cloudflare（备） | 带 | CF 按 ECS 回 HK/JP 节点，否则回美国 |

每个上游可用 `<PREFIX>_ECS` 变量独立覆盖，取值为 `on`（恒带）、`off`（恒不带）、`cf-only`（仅 Cloudflare 上游带）。例如把国内备也关掉：`DOMESTIC_FALLBACK_DOH_ECS=off`。

## 对冲与缓存

- `UPSTREAM_TIMEOUT_MS`（默认 1500）：单个上游超时。
- `HEDGE_DELAY_MS`（默认 800）：主用超过该延迟未成功则同时问备用，先成功先用；主用在窗口内成功则备用根本不发。设为 `0` 即主备双发。
- `CACHE_MAX_AGE_S`（默认 300，`0` 关闭）：热点回答按 answer 最小 TTL（上限该值）存 `caches.default`。带 ECS 的回答按客户端 /24（v6 /56）隔离存放，干净回答全局共享；缓存命中时改写 txid 后直接返回。

## 配置

所有配置都有默认值，一键部署时无需修改。

| 变量 | 默认值 |
|---|---|
| `DOH_PATH` | `/doh` |
| `DOMESTIC_DOH_URL` | `https://dns.alidns.com/dns-query` |
| `DOMESTIC_FALLBACK_DOH_URL` | `https://doh.pub/dns-query` |
| `GLOBAL_DOH_URL` | `https://dns.google/dns-query` |
| `GLOBAL_FALLBACK_DOH_URL` | `https://cloudflare-dns.com/dns-query` |
| `DOMESTIC_DOH_ECS` / `DOMESTIC_FALLBACK_DOH_ECS` | `on` |
| `GLOBAL_DOH_ECS` | `off` |
| `GLOBAL_FALLBACK_DOH_ECS` | `on` |
| `UPSTREAM_TIMEOUT_MS` | `1500` |
| `HEDGE_DELAY_MS` | `800` |
| `CACHE_MAX_AGE_S` | `300` |

国内域名规则来自 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) 的 `direct-list.txt`，每天自动更新。

## 注意
- 部分受限网络环境无法访问 .workers.dev 域名，需绑定自有域名或另外使用 CDN 以达到加速访问目的。
- ECS 地址优先取自 `X-Forwarded-For` 中最左侧的合法公网 IP；没有有效地址时回退到 `CF-Connecting-IP`，并自动掩码为 IPv4 `/24` 或 IPv6 `/56`。
- 最坏等待约 `HEDGE_DELAY_MS + UPSTREAM_TIMEOUT_MS`（默认约 2.3 秒，旧版串行约 6 秒）。
- 本项目不提供公共 DNS 服务的滥用防护，公开部署时建议配合 Cloudflare WAF 或限速规则。

## 本地开发

需要 Node.js 20 或更高版本。

```bash
npm install
npm run typecheck
npm test
npm run deploy:dry-run
```

## 许可证

MIT


