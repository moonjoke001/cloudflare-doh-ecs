import { toArrayBuffer, readU16, writeU16 } from "./binary";
import {
  buildDnsError,
  DnsFormatError,
  minAnswerTtl,
  parseDnsMessage,
  parseName,
  validateUpstreamResponse,
  type DnsMessageInfo
} from "./dns";
import { rewriteEcs } from "./ecs";
import {
  clientIpFromSingleHeader,
  clientIpFromXff,
  subnetForEcs,
  type EcsSubnet
} from "./ip";
import {
  ensureRules,
  isDomesticDomain,
  updateRules,
  type LoadedRules
} from "./rules";
import { readConfig, type Upstream, type WorkerConfig } from "./config";
import type { Env } from "./types";

const MAX_REQUEST_BYTES = 4096;
const MAX_RESPONSE_BYTES = 65535;
const ECS_IPV4_PREFIX = 24;
const ECS_IPV6_PREFIX = 56;
const DNS_CONTENT_TYPE = "application/dns-message";

// Workers 运行时提供 caches.default；@cloudflare/workers-types 旧版类型缺失时补声明。
declare const caches: CacheStorage & { default: Cache };

class UpstreamFailure extends Error {
  constructor(
    readonly reason: string,
    readonly detail?: string
  ) {
    super(reason);
    this.name = "UpstreamFailure";
  }
}

interface UpstreamFailureDiagnostic {
  reason: string;
  detail?: string;
}

function safeFetchErrorDetail(error: unknown): string {
  if (!(error instanceof Error)) return `non_error:${typeof error}`;
  return `${error.name}: ${error.message}`
    .replace(/https:\/\/[^\s"'<>]+/gi, "[url]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 240);
}

function upstreamFailureDiagnostic(error: unknown): UpstreamFailureDiagnostic {
  if (error instanceof UpstreamFailure) {
    return error.detail === undefined
      ? { reason: error.reason }
      : { reason: error.reason, detail: error.detail };
  }
  if (error instanceof DnsFormatError) return { reason: `dns_${error.message}` };
  return { reason: "unexpected_error" };
}

function logUpstreamFailure(
  group: "domestic" | "global",
  role: "primary" | "fallback",
  diagnostic: UpstreamFailureDiagnostic
): void {
  // 不记录查询域名、DNS 报文、客户端地址或自定义上游 URL。
  console.warn("doh_upstream_failed", { group, role, ...diagnostic });
}

function emptyResponse(status: number, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  return new Response(null, { status, headers });
}

function dnsResponse(
  body: Uint8Array,
  status = 200,
  extraHeaders?: HeadersInit
): Response {
  const headers = new Headers({
    "Content-Type": DNS_CONTENT_TYPE,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  if (extraHeaders !== undefined) {
    for (const [key, value] of new Headers(extraHeaders).entries()) {
      headers.set(key, value);
    }
  }
  return new Response(toArrayBuffer(body), { status, headers });
}

function contentTypeIsDns(request: Request): boolean {
  const value = request.headers.get("content-type");
  if (value === null) return false;
  return value.split(";", 1)[0]?.trim().toLowerCase() === DNS_CONTENT_TYPE;
}

function decodeBase64Url(value: string): Uint8Array | null {
  if (
    value.length === 0 ||
    value.length > Math.ceil(MAX_REQUEST_BYTES * 4 / 3) + 4 ||
    !/^[A-Za-z0-9_-]+={0,2}$/.test(value) ||
    value.length % 4 === 1
  ) {
    return null;
  }
  const unpadded = value.replace(/=+$/, "");
  const padding = "=".repeat((4 - (unpadded.length % 4)) % 4);
  try {
    const decoded = atob(unpadded.replace(/-/g, "+").replace(/_/g, "/") + padding);
    if (decoded.length > MAX_REQUEST_BYTES) return null;
    const output = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i += 1) output[i] = decoded.charCodeAt(i);
    return output;
  } catch {
    return null;
  }
}

async function readDnsRequest(request: Request, config: WorkerConfig): Promise<Response | Uint8Array> {
  const url = new URL(request.url);
  if (url.pathname !== config.path) return emptyResponse(404);

  if (request.method === "GET") {
    const values = url.searchParams.getAll("dns");
    if (values.length !== 1 || [...url.searchParams.keys()].some((key) => key !== "dns")) {
      return emptyResponse(400);
    }
    const decoded = decodeBase64Url(values[0] ?? "");
    return decoded ?? emptyResponse(400);
  }

  if (request.method === "POST") {
    if (url.search !== "") return emptyResponse(400);
    if (!contentTypeIsDns(request)) return emptyResponse(415);
    const declaredLength = request.headers.get("content-length");
    if (declaredLength !== null) {
      const parsed = Number(declaredLength);
      if (!Number.isFinite(parsed) || parsed < 0 || parsed > MAX_REQUEST_BYTES) {
        return emptyResponse(413);
      }
    }
    const buffer = await request.arrayBuffer();
    if (buffer.byteLength > MAX_REQUEST_BYTES) return emptyResponse(413);
    if (buffer.byteLength === 0) return emptyResponse(400);
    return new Uint8Array(buffer);
  }

  return emptyResponse(405, { Allow: "GET, POST" });
}

async function fetchUpstream(
  url: string,
  query: Uint8Array,
  timeoutMs: number
): Promise<Uint8Array> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response: Response;
    try {
      response = await fetch(url, {
        method: "POST",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          Accept: DNS_CONTENT_TYPE,
          "Content-Type": DNS_CONTENT_TYPE
        },
        body: toArrayBuffer(query)
      });
    } catch (error) {
      throw new UpstreamFailure(
        controller.signal.aborted ? "timeout" : "network_error",
        safeFetchErrorDetail(error)
      );
    }
    if (!response.ok) throw new UpstreamFailure(`http_status_${response.status}`);
    const type = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (type !== DNS_CONTENT_TYPE) throw new UpstreamFailure("invalid_content_type");
    const declaredLength = response.headers.get("content-length");
    if (declaredLength !== null && Number(declaredLength) > MAX_RESPONSE_BYTES) {
      throw new UpstreamFailure("response_too_large");
    }
    let buffer: ArrayBuffer;
    try {
      buffer = await response.arrayBuffer();
    } catch (error) {
      throw new UpstreamFailure(
        controller.signal.aborted ? "timeout" : "response_read_error",
        safeFetchErrorDetail(error)
      );
    }
    if (buffer.byteLength < 12 || buffer.byteLength > MAX_RESPONSE_BYTES) {
      throw new UpstreamFailure("invalid_response_size");
    }
    return new Uint8Array(buffer);
  } finally {
    clearTimeout(timeout);
  }
}

function isCloudflareUpstream(url: string): boolean {
  let hostname = "";
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  return (
    hostname === "cloudflare-dns.com" ||
    hostname === "one.one.one.one" ||
    hostname.endsWith(".cloudflare-dns.com")
  );
}

/** 按上游 ECS 作用域决定发带 ECS 版还是干净原版。 */
function queryForUpstream(
  withEcsQuery: Uint8Array,
  withoutEcsQuery: Uint8Array,
  upstream: Upstream
): { query: Uint8Array; withEcs: boolean } {
  switch (upstream.ecs) {
    case "on":
      return { query: withEcsQuery, withEcs: true };
    case "off":
      return { query: withoutEcsQuery, withEcs: false };
    case "cf-only":
      return isCloudflareUpstream(upstream.url)
        ? { query: withEcsQuery, withEcs: true }
        : { query: withoutEcsQuery, withEcs: false };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface UpstreamSuccess {
  body: Uint8Array;
  info: DnsMessageInfo;
  withEcs: boolean;
  role: "primary" | "fallback";
  upstreamHost: string;
}

async function tryUpstream(
  upstream: Upstream,
  query: Uint8Array,
  withEcs: boolean,
  parsed: DnsMessageInfo,
  group: "domestic" | "global",
  role: "primary" | "fallback",
  timeoutMs: number
): Promise<UpstreamSuccess | null> {
  try {
    const body = await fetchUpstream(upstream.url, query, timeoutMs);
    const info = validateUpstreamResponse(body, parsed);
    // 仅 NOERROR(0)/NXDOMAIN(3) 算合法结论：REFUSED/NOTIMP 等是“没答”，
    // 不能让它在竞速里抢先，堵死备胎给出真答案的机会。
    const rcode = info.flags & 0x000f;
    if (rcode !== 0 && rcode !== 3) {
      logUpstreamFailure(group, role, {
        reason: rcode === 2 ? "dns_servfail" : `dns_rcode_${rcode}`
      });
      return null;
    }
    return {
      body,
      info,
      withEcs,
      role,
      upstreamHost: new URL(upstream.url).hostname
    };
  } catch (error) {
    logUpstreamFailure(group, role, upstreamFailureDiagnostic(error));
    return null;
  }
}

function hexBytes(data: Uint8Array): string {
  let out = "";
  for (const byte of data) out += byte.toString(16).padStart(2, "0");
  return out;
}

/**
 * 热点缓存键：ECS 个性化回答按子网隔离存放（同 /24 共享），
 * 干净回答全客户端共享。ruleName 为空（不可规范化）时不缓存。
 */
function cacheKeyFor(
  parsed: DnsMessageInfo,
  subnet: EcsSubnet | null,
  withEcs: boolean
): Request | null {
  const name = parsed.question.name.ruleName;
  if (name === null) return null;
  const scope =
    withEcs && subnet !== null
      ? `ecs-${subnet.family}-${subnet.prefixLength}-${hexBytes(subnet.network)}`
      : "noecs";
  const qtype = parsed.question.type;
  const qclass = parsed.question.class;
  return new Request(`https://doh-cache.invalid/${qtype}/${qclass}/${scope}/${name}`);
}

async function cacheLookup(key: Request | null): Promise<Uint8Array | null> {
  if (key === null) return null;
  try {
    if (typeof caches === "undefined") return null;
    const hit = await caches.default.match(key);
    if (hit === undefined) return null;
    const body = new Uint8Array(await hit.arrayBuffer());
    if (body.length < 12) return null;
    return body;
  } catch {
    return null;
  }
}

async function cacheStore(
  key: Request | null,
  success: UpstreamSuccess,
  maxAgeS: number,
  ctx?: ExecutionContext
): Promise<void> {
  if (key === null || maxAgeS === 0) return;
  const ttl = minAnswerTtl(success.info);
  if (ttl === null || ttl <= 0) return;
  const age = Math.min(ttl, maxAgeS);
  const stored = new Response(toArrayBuffer(success.body), {
    headers: {
      "Content-Type": DNS_CONTENT_TYPE,
      "Cache-Control": `public, max-age=${age}`
    }
  });
  const put = (async (): Promise<void> => {
    try {
      if (typeof caches !== "undefined") await caches.default.put(key, stored);
    } catch {
      // 缓存失败不影响本次回答。
    }
  })();
  if (ctx !== undefined && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(put);
  } else {
    await put;
  }
}

/** 调试头：DECIDO 开启时回带分流决策，便于线上排查。 */
function debugHeaders(
  config: WorkerConfig,
  env: Env,
  parts: {
    group?: string;
    domestic?: boolean;
    rulesVersion?: string | null;
    cache?: string;
    subnet?: string | null;
    upstream?: string;
    ech?: string;
  }
): HeadersInit | undefined {
  if (config.debugHeaders !== true) return undefined;
  const bits = [
    parts.cache !== undefined ? `cache=${parts.cache}` : null,
    parts.group !== undefined ? `group=${parts.group}` : null,
    parts.domestic !== undefined ? `domestic=${parts.domestic}` : null,
    parts.rulesVersion !== undefined
      ? `rules=${parts.rulesVersion === null ? "none" : parts.rulesVersion.slice(11, 19)}`
      : null,
    parts.subnet !== undefined ? `ecs=${parts.subnet ?? "none"}` : null,
    parts.upstream !== undefined ? `up=${parts.upstream}` : null,
    parts.ech !== undefined ? `ech=${parts.ech}` : null
  ].filter((v): v is string => v !== null);
  return { "x-doh-debug": bits.join(" ") };
}

function subnetLabel(subnet: EcsSubnet | null): string {
  if (subnet === null) return "none";
  return `${[...subnet.network].join(".")}/${subnet.prefixLength}`;
}

const SVCB_ECH_KEY = 5;
const HTTPS_TYPE = 65;

/**
 * 扫描 SVCB/HTTPS rdata 的参数区，判断是否带 ech（SvcParamKey=5）。
 * rdata 布局：priority(2) + target(name) + (key(2)+len(2)+value)*。
 */
export function svcbHasEch(data: Uint8Array, start: number, end: number): boolean {
  if (start + 2 > end) return false;
  let cursor = start + 2; // 跳过 priority
  try {
    const target = parseName(data, cursor);
    cursor = target.nextOffset;
  } catch {
    return false;
  }
  while (cursor + 4 <= end) {
    const key = readU16(data, cursor);
    const length = readU16(data, cursor + 2);
    if (cursor + 4 + length > end) return false;
    if (key === SVCB_ECH_KEY) return true;
    cursor += 4 + length;
  }
  return false;
}

function answerHasEch(body: Uint8Array, info: DnsMessageInfo): boolean {
  return info.answers.some(
    (record) => record.type === HTTPS_TYPE && svcbHasEch(body, record.rdataStart, record.rdataEnd)
  );
}

/**
 * HTTPS(65) 查询且上游答案没带 ech 时，向 Cloudflare 官方解析器补查同一条
 * HTTPS 记录：CF 托管站若开了 ECH，官方解析器的答案里一定带 ech 配置。
 * 拿到带 ech 的答案就整体替换返回（同一权威数据），拿不到维持原答案。
 * 仅对全球组启用：国内域名单独多打一发查询不划算，且 CF 站点极少命中。
 */
async function maybeUpgradeEch(
  cleanQuery: Uint8Array,
  winner: UpstreamSuccess,
  parsed: DnsMessageInfo,
  config: WorkerConfig,
  group: "domestic" | "global"
): Promise<Uint8Array | null> {
  if (parsed.question.type !== HTTPS_TYPE || group !== "global") return null;
  if (answerHasEch(winner.body, winner.info)) return null;
  try {
    const body = await fetchUpstream(config.global[0]!.url, cleanQuery, config.upstreamTimeoutMs);
    const info = validateUpstreamResponse(body, parsed);
    const rcode = info.flags & 0x000f;
    if (rcode !== 0 && rcode !== 3) return null;
    if (!answerHasEch(body, info)) return null;
    return body;
  } catch {
    return null;
  }
}

async function handleDns(
  request: Request,
  env: Env,
  config: WorkerConfig,
  ctx?: ExecutionContext
): Promise<Response> {
  const readResult = await readDnsRequest(request, config);
  if (readResult instanceof Response) return readResult;
  const originalQuery = readResult;

  let parsed;
  try {
    parsed = parseDnsMessage(originalQuery);
  } catch {
    return dnsResponse(buildDnsError(originalQuery, 1));
  }

  let withEcsQuery: Uint8Array;
  let withoutEcsQuery: Uint8Array;
  let subnet: EcsSubnet | null = null;
  try {
    const ip =
      clientIpFromXff(request.headers.get("x-forwarded-for")) ??
      clientIpFromSingleHeader(request.headers.get("cf-connecting-ip"));
    subnet = subnetForEcs(ip, ECS_IPV4_PREFIX, ECS_IPV6_PREFIX);
    withEcsQuery = rewriteEcs(originalQuery, parsed, subnet);
    withoutEcsQuery = rewriteEcs(originalQuery, parsed, null);
  } catch (error) {
    if (error instanceof DnsFormatError) {
      return dnsResponse(buildDnsError(originalQuery, 1, parsed.question));
    }
    return dnsResponse(buildDnsError(originalQuery, 2, parsed.question));
  }

  let domestic = false;
  let rules: LoadedRules | null = null;
  const ruleName = parsed.question.name.ruleName;
  if (ruleName !== null) {
    rules = await ensureRules(env);
    domestic = rules !== null && isDomesticDomain(rules, ruleName);
  }
  const upstreams = domestic ? config.domestic : config.global;
  const group = domestic ? "domestic" : "global";

  // 主备都按“带 ECS”查一遍键再按“干净”查一遍；命中任一直接返回（改写 txid 回原查询）。
  if (config.cacheMaxAgeS > 0) {
    for (const upstream of upstreams) {
      const selection = queryForUpstream(withEcsQuery, withoutEcsQuery, upstream);
      const hit = await cacheLookup(cacheKeyFor(parsed, subnet, selection.withEcs));
      if (hit !== null) {
        writeU16(hit, 0, parsed.id);
        return dnsResponse(
          hit,
          200,
          debugHeaders(config, env, {
            cache: "hit",
            group,
            domestic,
            rulesVersion: rules?.version ?? null,
            subnet: subnetLabel(subnet)
          })
        );
      }
    }
  }

  const primary = queryForUpstream(withEcsQuery, withoutEcsQuery, upstreams[0]!);
  const fallback = queryForUpstream(withEcsQuery, withoutEcsQuery, upstreams[1]!);
  const runPrimary = (): Promise<UpstreamSuccess | null> =>
    tryUpstream(
      upstreams[0]!,
      primary.query,
      primary.withEcs,
      parsed,
      group,
      "primary",
      config.upstreamTimeoutMs
    );
  const runFallback = (): Promise<UpstreamSuccess | null> =>
    tryUpstream(
      upstreams[1]!,
      fallback.query,
      fallback.withEcs,
      parsed,
      group,
      "fallback",
      config.upstreamTimeoutMs
    );

  let winner: UpstreamSuccess | null;
  if (config.hedgeDelayMs === 0) {
    // 双发：主备同时问，主用成功优先，否则取备。
    const [first, second] = await Promise.all([runPrimary(), runFallback()]);
    winner = first ?? second;
  } else {
    // 窗口内主用先成功 → 备用根本不发；主用慢 → 触发对冲，主备谁先成功用谁。
    const primaryPromise = runPrimary();
    const early: { tag: "hit"; r: UpstreamSuccess | null } | { tag: "timer" } =
      await Promise.race([
        primaryPromise.then((r) => ({ tag: "hit" as const, r })),
        sleep(config.hedgeDelayMs).then(() => ({ tag: "timer" as const }))
      ]);
    if (early.tag === "hit") {
      winner = early.r;
      if (winner === null) winner = await runFallback();
    } else {
      const [p, f] = await Promise.all([primaryPromise, runFallback()]);
      winner = p ?? f;
    }
  }

  // 仅在当前国内或国外组内主备尝试，不进行跨组回退。
  if (winner === null) {
    return dnsResponse(buildDnsError(originalQuery, 2, parsed.question));
  }

  // HTTPS 查询且全球组答案缺 ech 时用 CF 官方解析器补齐；升级后连同最终
  // 报文一起进缓存，避免“首查带 ECH、缓存命中后丢失”。
  const echBody = await maybeUpgradeEch(withoutEcsQuery, winner, parsed, config, group);
  const finalBody = echBody ?? winner.body;
  if (echBody !== null) {
    winner = { ...winner, body: finalBody };
  }

  await cacheStore(
    cacheKeyFor(parsed, subnet, winner.withEcs),
    winner,
    config.cacheMaxAgeS,
    ctx
  );
  return dnsResponse(
    finalBody,
    200,
    debugHeaders(config, env, {
      cache: `miss/${winner.role}`,
      group,
      domestic,
      rulesVersion: rules?.version ?? null,
      subnet: subnetLabel(subnet),
      upstream: winner.upstreamHost,
      ...(parsed.question.type === HTTPS_TYPE
        ? { ech: echBody !== null ? "on" : "off" }
        : {})
    })
  );
}

export async function handleRequest(
  request: Request,
  env: Env,
  ctx?: ExecutionContext
): Promise<Response> {
  let config: WorkerConfig;
  try {
    config = readConfig(env);
  } catch {
    const url = new URL(request.url);
    const expectedPath = env.DOH_PATH ?? "/doh";
    if (url.pathname !== expectedPath) return emptyResponse(404);
    let query = new Uint8Array();
    if (request.method === "POST") {
      try {
        const buffer = await request.arrayBuffer();
        if (buffer.byteLength <= MAX_REQUEST_BYTES) query = new Uint8Array(buffer);
      } catch {
        // 配置错误时也只返回 DNS 或空响应，不泄露具体环境变量。
      }
    }
    return dnsResponse(buildDnsError(query, 2));
  }
  return handleDns(request, env, config, ctx);
}

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handleRequest(request, env, ctx);
  },

  scheduled(
    _controller: ScheduledController,
    env: Env,
    ctx: ExecutionContext
  ): void {
    ctx.waitUntil(
      updateRules(env).then(
        () => undefined,
        () => undefined
      )
    );
  }
} satisfies ExportedHandler<Env>;
