import { readConfig } from "../src/config";
import { MemoryKv } from "./helpers";

describe("worker configuration", () => {
  const base = () => ({ RULES_KV: new MemoryKv().asBinding() });

  it("uses safe defaults and accepts valid overrides", () => {
    expect(readConfig(base())).toMatchObject({
      path: "/doh",
      pathAlias: "/dns-query",
      domestic: [
        { url: "https://dns.alidns.com/dns-query", ecs: "on" },
        { url: "https://doh.pub/dns-query", ecs: "on" }
      ],
      global: [
        { url: "https://cloudflare-dns.com/dns-query", ecs: "on" },
        { url: "https://dns.google/dns-query", ecs: "off" }
      ],
      upstreamTimeoutMs: 1500,
      hedgeDelayMs: 800,
      cacheMaxAgeS: 300
    });
    expect(
      readConfig({
        ...base(),
        DOH_PATH: "/private-doh",
        GLOBAL_DOH_URL: "https://resolver.example/dns-query",
        GLOBAL_FALLBACK_DOH_URL: "https://backup.example/dns-query",
        GLOBAL_DOH_ECS: "cf-only",
        UPSTREAM_TIMEOUT_MS: "2000",
        HEDGE_DELAY_MS: "0",
        CACHE_MAX_AGE_S: "0"
      })
    ).toMatchObject({
      path: "/private-doh",
      pathAlias: null,
      global: [
        { url: "https://resolver.example/dns-query", ecs: "cf-only" },
        { url: "https://backup.example/dns-query", ecs: "off" }
      ],
      upstreamTimeoutMs: 2000,
      hedgeDelayMs: 0,
      cacheMaxAgeS: 0
    });
  });

  it.each([
    { DOH_PATH: "dns-query" },
    { DOH_PATH: "//evil" },
    { GLOBAL_DOH_URL: "http://8.8.8.8/dns-query" },
    { GLOBAL_DOH_URL: "https://user:pass@example.com/dns-query" },
    { GLOBAL_DOH_URL: "https://127.0.0.1/dns-query" },
    { GLOBAL_DOH_URL: "https://[::1]/dns-query" },
    { GLOBAL_DOH_URL: "https://example.com/dns-query?target=x" },
    { DOMESTIC_FALLBACK_DOH_URL: "https://127.0.0.1/dns-query" },
    { GLOBAL_DOH_ECS: "sometimes" },
    { UPSTREAM_TIMEOUT_MS: "50" },
    { UPSTREAM_TIMEOUT_MS: "abc" },
    { HEDGE_DELAY_MS: "-1" },
    { CACHE_MAX_AGE_S: "99999999" }
  ])("rejects unsafe config %#", (override) => {
    expect(() => readConfig({ ...base(), ...override })).toThrow();
  });
});
