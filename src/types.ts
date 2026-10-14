export interface Env {
  RULES_KV: KVNamespace;
  DOH_PATH?: string;
  DOMESTIC_DOH_URL?: string;
  DOMESTIC_FALLBACK_DOH_URL?: string;
  GLOBAL_DOH_URL?: string;
  GLOBAL_FALLBACK_DOH_URL?: string;
  // ECS 作用域（每个上游独立）："on" 恒带、"off" 恒不带、
  // "cf-only" 仅上游是 Cloudflare DoH 时带。默认国内组全 on，
  // 国外主（Google）off、国外备（Cloudflare）on。
  DOMESTIC_DOH_ECS?: string;
  DOMESTIC_FALLBACK_DOH_ECS?: string;
  GLOBAL_DOH_ECS?: string;
  GLOBAL_FALLBACK_DOH_ECS?: string;
  // 上游单次超时毫秒（默认 1500），对冲延迟毫秒（默认 800，0 = 主备双发）。
  UPSTREAM_TIMEOUT_MS?: string;
  HEDGE_DELAY_MS?: string;
  // 热点缓存上限秒（默认 300，0 = 关闭）。
  CACHE_MAX_AGE_S?: string;
  // "on" 时响应带 x-doh-debug 头（分流决策/规则版本），排查线上用。
  DEBUG_HEADERS?: string;
}

export interface RuleManifest {
  active: string;
  previous: string | null;
  sha256: string;
  size: number;
  updatedAt: string;
}
