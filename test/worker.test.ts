import { readU16, toArrayBuffer, writeU16, writeU32 } from "../src/binary";
import { parseDnsMessage } from "../src/dns";
import { handleRequest } from "../src/index";
import { resetRuleCacheForTest } from "../src/rules";
import { envWithRules, makeQuery, makeResponseFromQuery, MemoryKv } from "./helpers";

function base64Url(data: Uint8Array): string {
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("DoH worker", () => {
  beforeEach(() => {
    resetRuleCacheForTest();
    vi.restoreAllMocks();
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
  });

  it("routes domestic POST to AliDNS and injects ECS", async () => {
    const { env } = await envWithRules();
    let destination = "";
    let forwarded = new Uint8Array();
    let redirect: RequestRedirect | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        destination = String(input);
        forwarded = new Uint8Array(init?.body as ArrayBuffer);
        redirect = init?.redirect;
        return new Response(toArrayBuffer(makeResponseFromQuery(forwarded)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const query = makeQuery("www.qq.com", 1);
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: {
          "content-type": "application/dns-message",
          "x-forwarded-for": "198.51.100.1, 8.8.4.123"
        },
        body: toArrayBuffer(query)
      }),
      env
    );
    expect(response.status).toBe(200);
    expect(destination).toBe("https://dns.alidns.com/dns-query");
    expect(redirect).toBe("manual");
    expect(parseDnsMessage(forwarded).opt).not.toBeNull();
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("caches hot answers per ECS scope and serves the second hit offline", async () => {
    const { env } = await envWithRules();
    const cache = new Map<string, Response>();
    const cachesStub = {
      default: {
        async match(key: Request): Promise<Response | undefined> {
          const hit = cache.get(key.url);
          return hit === undefined ? undefined : hit.clone();
        },
        async put(key: Request, value: Response): Promise<void> {
          cache.set(key.url, value.clone());
        }
      }
    };
    vi.stubGlobal("caches", cachesStub);
    let calls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
        calls += 1;
        const sent = new Uint8Array(init?.body as ArrayBuffer);
        // 真上游回干净回答：只取 question 段再拼 answer（带 ECS 查询尾部有 OPT，
        // 直接 append 会被误解析成 answer，TTL=0 导致跳过缓存）。
        const parsed = parseDnsMessage(sent);
        const qEnd = parsed.question.endOffset;
        const answer = new Uint8Array(16);
        answer[0] = 0xc0;
        answer[1] = 0x0c;
        writeU16(answer, 2, 1);
        writeU16(answer, 4, 1);
        writeU32(answer, 6, 120);
        writeU16(answer, 10, 4);
        answer.set([1, 2, 3, 4], 12);
        const out = new Uint8Array(qEnd + answer.length);
        out.set(sent.slice(0, qEnd));
        out.set(answer, qEnd);
        writeU16(out, 2, (parsed.flags & 0x7800) | 0x8180);
        writeU16(out, 6, 1);
        writeU16(out, 10, 0);
        return new Response(toArrayBuffer(out), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const post = (id: number): Request =>
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: {
          "content-type": "application/dns-message",
          "x-forwarded-for": "1.2.3.9"
        },
        body: toArrayBuffer(makeQuery("www.youtube.com", 1, { id }))
      });
    const first = await handleRequest(post(0xaaaa), env);
    expect(first.status).toBe(200);
    expect(calls).toBe(1);
    expect(cache.size).toBe(1);
    // 第二次不同 txid 同一域名：命中缓存，不再出网（txid 被改回本次查询）。
    const second = await handleRequest(post(0xbbbb), env);
    expect(second.status).toBe(200);
    expect(calls).toBe(1);
    const body = new Uint8Array(await second.arrayBuffer());
    expect(readU16(body, 0)).toBe(0xbbbb);
    expect(readU16(body, 6)).toBe(1);
  });

  it("isolates ECS-scoped cache entries across client subnets", async () => {
    const { env } = await envWithRules();
    const cache = new Map<string, Response>();
    vi.stubGlobal("caches", {
      default: {
        async match(key: Request): Promise<Response | undefined> {
          const hit = cache.get(key.url);
          return hit === undefined ? undefined : hit.clone();
        },
        async put(key: Request, value: Response): Promise<void> {
          cache.set(key.url, value.clone());
        }
      }
    });
    let calls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        calls += 1;
        if (String(input).includes("dns.google")) {
          return new Response(null, { status: 503 });
        }
        const sent = new Uint8Array(init?.body as ArrayBuffer);
        const parsed = parseDnsMessage(sent);
        // 真上游回的是干净回答：只取 question 段再拼 answer（不能直接 append，
        // 否则带 ECS 查询尾部的 OPT 会被误解析成 answer，TTL=0 导致跳过缓存）。
        const qEnd = parsed.question.endOffset;
        const answer = new Uint8Array(16);
        answer[0] = 0xc0;
        answer[1] = 0x0c;
        writeU16(answer, 2, 1);
        writeU16(answer, 4, 1);
        writeU32(answer, 6, 60);
        writeU16(answer, 10, 4);
        answer.set([5, 6, 7, 8], 12);
        const out = new Uint8Array(qEnd + answer.length);
        out.set(sent.slice(0, qEnd));
        out.set(answer, qEnd);
        writeU16(out, 2, (parsed.flags & 0x7800) | 0x8180);
        writeU16(out, 6, 1);
        writeU16(out, 10, 0);
        return new Response(toArrayBuffer(out), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const post = (xff: string): Request =>
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: {
          "content-type": "application/dns-message",
          "x-forwarded-for": xff
        },
        body: toArrayBuffer(makeQuery("example.net", 1))
      });
    // global 组：主 CF(on)成功并按客户端 /24 缓存（mock 让 Google 恒 503 以防对冲走到它）。
    expect((await handleRequest(post("1.2.3.9"), env)).status).toBe(200);
    expect(calls).toBe(1);
    // 同一子网再查：主的 ecs 键命中，不再出网。
    expect((await handleRequest(post("1.2.3.200"), env)).status).toBe(200);
    expect(calls).toBe(1);
    // 不同子网：ecs 键隔离，miss 后重新出网并写入第二条。
    expect((await handleRequest(post("9.9.9.9"), env)).status).toBe(200);
    expect(calls).toBe(2);
    expect(cache.size).toBe(2);
  });

  it("routes foreign GET to Cloudflare and supports base64url", async () => {
    const { env } = await envWithRules();
    const destinations: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        destinations.push(String(input));
        const body = new Uint8Array(init?.body as ArrayBuffer);
        return new Response(toArrayBuffer(makeResponseFromQuery(body)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const query = makeQuery("example.net", 65);
    const response = await handleRequest(
      new Request(`https://worker.example/doh?dns=${base64Url(query)}`, {
        headers: { "x-forwarded-for": "2001:4860:4860::8888" }
      }),
      env
    );
    expect(response.status).toBe(200);
    // type-65 且答案缺 ech 时会向 CF 官方解析器补查一次（仍无 ech 则返回原答案）。
    expect(destinations).toEqual([
      "https://cloudflare-dns.com/dns-query",
      "https://cloudflare-dns.com/dns-query"
    ]);
  });

  function ecsBytes(body: Uint8Array): number[] | null {
    // 返回报文中 ECS 选项的原始字节；无 ECS 时返回 null。
    const parsed = parseDnsMessage(body);
    const opt = parsed.opt;
    if (opt === null) return null;
    let offset = opt.rdataStart;
    while (offset + 4 <= opt.rdataEnd) {
      const code = readU16(body, offset);
      const length = readU16(body, offset + 2);
      const end = offset + 4 + length;
      if (code === 8) return Array.from(body.slice(offset, end));
      offset = end;
    }
    return null;
  }

  it("falls back to CF-Connecting-IP when XFF has no public address", async () => {
    const { env } = await envWithRules();
    const seen: Array<{ url: string; body: Uint8Array }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const body = new Uint8Array(init?.body as ArrayBuffer);
        seen.push({ url: String(input), body });
        if (seen.length === 1) return new Response(null, { status: 503 });
        return new Response(toArrayBuffer(makeResponseFromQuery(body)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const query = makeQuery("example.net", 66);
    const response = await handleRequest(
      new Request(`https://worker.example/doh?dns=${base64Url(query)}`, {
        headers: {
          "x-forwarded-for": "10.0.0.1, 192.168.1.1",
          "cf-connecting-ip": "8.8.4.123"
        }
      }),
      env
    );
    expect(response.status).toBe(200);
    // 主用 Cloudflare 默认带 ECS，IP 取自 cf-connecting-ip。
    expect(seen[0]?.url).toBe("https://cloudflare-dns.com/dns-query");
    expect(ecsBytes(seen[0]?.body ?? new Uint8Array())).toEqual([
      0, 8, 0, 7, 0, 1, 24, 0, 8, 8, 4
    ]);
    // 备 Google 默认不带 ECS（干净原版）。
    expect(seen[1]?.url).toBe("https://dns.google/dns-query");
    expect(ecsBytes(seen[1]?.body ?? new Uint8Array())).toBeNull();
  });

  it("sends ECS to domestic primary and strips it for opt-out fallback", async () => {
    const { env } = await envWithRules();
    const seen: Array<{ url: string; body: Uint8Array }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const body = new Uint8Array(init?.body as ArrayBuffer);
        seen.push({ url: String(input), body });
        return new Response(toArrayBuffer(makeResponseFromQuery(body)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: {
          "content-type": "application/dns-message",
          "x-forwarded-for": "1.2.3.4, 8.8.4.123"
        },
        body: toArrayBuffer(makeQuery("www.qq.com", 1))
      }),
      {
        ...env,
        DOMESTIC_FALLBACK_DOH_ECS: "off",
        HEDGE_DELAY_MS: "0"
      }
    );
    expect(response.status).toBe(200);
    // HEDGE_DELAY_MS=0 双发：主备都被问到。
    expect(seen.map((s) => s.url)).toEqual([
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ]);
    // 主用带 ECS（1.2.3.0/24），备因 off 被 strip。
    expect(ecsBytes(seen[0]?.body ?? new Uint8Array())?.slice(4)).toEqual([
      0, 1, 24, 0, 1, 2, 3
    ]);
    expect(ecsBytes(seen[1]?.body ?? new Uint8Array())).toBeNull();
  });

  it("supports cf-only scope: ECS only for Cloudflare upstreams", async () => {
    const { env } = await envWithRules();
    const seen: Array<{ url: string; body: Uint8Array }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const body = new Uint8Array(init?.body as ArrayBuffer);
        seen.push({ url: String(input), body });
        if (seen.length === 1) return new Response(null, { status: 503 });
        return new Response(toArrayBuffer(makeResponseFromQuery(body)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: {
          "content-type": "application/dns-message",
          "x-forwarded-for": "203.0.113.9"
        },
        body: toArrayBuffer(makeQuery("example.net", 1))
      }),
      {
        ...env,
        GLOBAL_DOH_URL: "https://dns.google/dns-query",
        GLOBAL_DOH_ECS: "cf-only",
        GLOBAL_FALLBACK_DOH_URL: "https://dns10.quad9.net/dns-query",
        GLOBAL_FALLBACK_DOH_ECS: "cf-only"
      }
    );
    expect(response.status).toBe(200);
    // 两家都不是 Cloudflare，都拿干净原版。
    expect(seen.map((s) => s.url)).toEqual([
      "https://dns.google/dns-query",
      "https://dns10.quad9.net/dns-query"
    ]);
    expect(ecsBytes(seen[0]?.body ?? new Uint8Array())).toBeNull();
    expect(ecsBytes(seen[1]?.body ?? new Uint8Array())).toBeNull();
  });

  it("returns DNS SERVFAIL after exhausting the domestic group", async () => {
    const { env } = await envWithRules();
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        calls.push(String(input));
        throw new TypeError("request to https://private.example/secret failed");
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("qq.com"))
      }),
      env
    );
    const body = new Uint8Array(await response.arrayBuffer());
    expect(readU16(body, 2) & 0x000f).toBe(2);
    expect(calls).toEqual([
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ]);
    expect(console.warn).toHaveBeenNthCalledWith(1, "doh_upstream_failed", {
      group: "domestic",
      role: "primary",
      reason: "network_error",
      detail: "TypeError: request to [url] failed"
    });
  });

  it("falls back from Cloudflare to Google without crossing groups", async () => {
    const { env } = await envWithRules();
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        calls.push(String(input));
        if (calls.length === 1) return new Response(null, { status: 503 });
        const body = new Uint8Array(init?.body as ArrayBuffer);
        return new Response(toArrayBuffer(makeResponseFromQuery(body)), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("example.net"))
      }),
      env
    );
    expect(calls).toEqual([
      "https://cloudflare-dns.com/dns-query",
      "https://dns.google/dns-query"
    ]);
    expect(console.warn).toHaveBeenCalledWith("doh_upstream_failed", {
      group: "global",
      role: "primary",
      reason: "http_status_503"
    });
    expect(readU16(new Uint8Array(await response.arrayBuffer()), 2) & 0xf).toBe(0);
  });

  it("falls back from AliDNS when it returns DNS SERVFAIL", async () => {
    const { env } = await envWithRules();
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        calls.push(String(input));
        const body = new Uint8Array(init?.body as ArrayBuffer);
        const dnsBody = makeResponseFromQuery(body);
        if (calls.length === 1) dnsBody[3] = ((dnsBody[3] ?? 0) & 0xf0) | 2;
        return new Response(toArrayBuffer(dnsBody), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("qq.com"))
      }),
      env
    );
    expect(calls).toEqual([
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ]);
    expect(console.warn).toHaveBeenCalledWith("doh_upstream_failed", {
      group: "domestic",
      role: "primary",
      reason: "dns_servfail"
    });
    expect(readU16(new Uint8Array(await response.arrayBuffer()), 2) & 0xf).toBe(0);
  });

  it("returns FORMERR for malformed DNS and empty HTTP errors for bad transport", async () => {
    const { env } = await envWithRules();
    const malformed = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(Uint8Array.of(1, 2, 3))
      }),
      env
    );
    expect(malformed.headers.get("content-type")).toBe("application/dns-message");
    expect(readU16(new Uint8Array(await malformed.arrayBuffer()), 2) & 0xf).toBe(1);

    const badGet = await handleRequest(
      new Request("https://worker.example/doh?dns=***"),
      env
    );
    expect(badGet.status).toBe(400);
    expect(await badGet.text()).toBe("");

    const wrongPath = await handleRequest(new Request("https://worker.example/"), env);
    expect(wrongPath.status).toBe(404);
    expect(await wrongPath.text()).toBe("");

    const wrongType = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}"
      }),
      env
    );
    expect(wrongType.status).toBe(415);
  });

  it("rejects invalid upstream response identity", async () => {
    const { env } = await envWithRules();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
        const body = makeResponseFromQuery(new Uint8Array(init?.body as ArrayBuffer));
        body[0] = 0;
        body[1] = 1;
        return new Response(toArrayBuffer(body), {
          headers: { "content-type": "application/dns-message" }
        });
      })
    );
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("example.net"))
      }),
      env
    );
    const body = new Uint8Array(await response.arrayBuffer());
    expect(readU16(body, 2) & 0xf).toBe(2);
  });

  it("returns SERVFAIL without leaking invalid environment configuration", async () => {
    const env = {
      RULES_KV: new MemoryKv().asBinding(),
      GLOBAL_DOH_URL: "http://127.0.0.1/dns-query"
    };
    const response = await handleRequest(
      new Request("https://worker.example/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: toArrayBuffer(makeQuery("example.net"))
      }),
      env
    );
    expect(response.status).toBe(200);
    expect(readU16(new Uint8Array(await response.arrayBuffer()), 2) & 0xf).toBe(2);
  });
});
