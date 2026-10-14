import { isGlobalUnicast, parseIp } from "./ip";
import { parseRelayDomains } from "./relay";
import type { Env } from "./types";

const DEFAULT_DOMESTIC = "https://dns.alidns.com/dns-query";
const DEFAULT_DOMESTIC_FALLBACK = "https://doh.pub/dns-query";
const DEFAULT_GLOBAL = "https://cloudflare-dns.com/dns-query";
const DEFAULT_GLOBAL_FALLBACK = "https://dns.google/dns-query";
const DEFAULT_PATH = "/doh";

export type EcsScope = "on" | "off" | "cf-only";

export interface Upstream {
  url: string;
  ecs: EcsScope;
}

export interface WorkerConfig {
  path: string;
  domestic: readonly [Upstream, Upstream];
  global: readonly [Upstream, Upstream];
  upstreamTimeoutMs: number;
  hedgeDelayMs: number;
  cacheMaxAgeS: number;
  debugHeaders: boolean;
  // AI 中继：命中域名的 A/HTTPS 改指自建 TCP 中继，其余解析不受影响。
  relayDomains: readonly string[];
  relayIpv4: Uint8Array | null;
  // 兼容旧配置：保留纯 URL 数组供外部引用。
  domesticUrls: readonly [string, string];
  globalUrls: readonly [string, string];
}


function validatePath(value: string | undefined): string {
  const path = value ?? DEFAULT_PATH;
  if (
    !path.startsWith("/") ||
    path.startsWith("//") ||
    path.includes("?") ||
    path.includes("#") ||
    path.includes("\\") ||
    path.length > 256
  ) {
    throw new Error("invalid_doh_path");
  }
  return path;
}

function validateUpstream(value: string | undefined, fallback: string): string {
  let url: URL;
  try {
    url = new URL(value ?? fallback);
  } catch {
    throw new Error("invalid_upstream_url");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== "" ||
    url.search !== ""
  ) {
    throw new Error("invalid_upstream_url");
  }

  let hostname = url.hostname;
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    hostname = hostname.slice(1, -1);
  }
  const literal = parseIp(hostname);
  if (literal !== null && !isGlobalUnicast(literal)) {
    throw new Error("private_upstream_literal");
  }
  return url.toString();
}

function parseEcsScope(value: string | undefined, fallback: EcsScope): EcsScope {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === "on" || normalized === "off" || normalized === "cf-only") {
    return normalized;
  }
  throw new Error("invalid_ecs_scope");
}

function parseRelayIpv4(value: string | undefined): Uint8Array | null {
  if (value === undefined || value.trim() === "") return null;
  const parsed = parseIp(value.trim());
  if (parsed === null || parsed.family !== 1 || !isGlobalUnicast(parsed)) {
    throw new Error("invalid_relay_ipv4");
  }
  return parsed.bytes;
}

function parseBoundedInt(
  value: string | undefined,
  fallback: number,
  min: number,
  max: number,
  code: string
): number {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(code);
  }
  return parsed;
}

export function readConfig(env: Env): WorkerConfig {
  const domestic: readonly [Upstream, Upstream] = [
    {
      url: validateUpstream(env.DOMESTIC_DOH_URL, DEFAULT_DOMESTIC),
      ecs: parseEcsScope(env.DOMESTIC_DOH_ECS, "on")
    },
    {
      url: validateUpstream(env.DOMESTIC_FALLBACK_DOH_URL, DEFAULT_DOMESTIC_FALLBACK),
      ecs: parseEcsScope(env.DOMESTIC_FALLBACK_DOH_ECS, "on")
    }
  ];
  const global: readonly [Upstream, Upstream] = [
    {
      url: validateUpstream(env.GLOBAL_DOH_URL, DEFAULT_GLOBAL),
      ecs: parseEcsScope(env.GLOBAL_DOH_ECS, "on")
    },
    {
      url: validateUpstream(env.GLOBAL_FALLBACK_DOH_URL, DEFAULT_GLOBAL_FALLBACK),
      ecs: parseEcsScope(env.GLOBAL_FALLBACK_DOH_ECS, "off")
    }
  ];
  return {
    path: validatePath(env.DOH_PATH),
    domestic,
    global,
    upstreamTimeoutMs: parseBoundedInt(env.UPSTREAM_TIMEOUT_MS, 1500, 200, 10000, "invalid_timeout"),
    hedgeDelayMs: parseBoundedInt(env.HEDGE_DELAY_MS, 800, 0, 5000, "invalid_hedge_delay"),
    cacheMaxAgeS: parseBoundedInt(env.CACHE_MAX_AGE_S, 300, 0, 86400, "invalid_cache_age"),
    debugHeaders: env.DEBUG_HEADERS === "on",
    relayDomains: parseRelayDomains(env.RELAY_DOMAINS),
    relayIpv4: parseRelayIpv4(env.RELAY_IPV4),
    domesticUrls: [domestic[0].url, domestic[1].url],
    globalUrls: [global[0].url, global[1].url]
  };
}
