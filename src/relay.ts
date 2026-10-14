import { concatBytes, readU16, writeU16, writeU32 } from "./binary";
import { SVCB_ALPN_KEY, SVCB_ECH_KEY, TYPE_A, HTTPS_TYPE } from "./ech";
import type { DnsMessageInfo } from "./dns";

const RELAY_TTL_S = 120;
// 钉地址（x.com → CF 确认 IP）走短 TTL：CF 收纳/退出站点时及时跟随。
const PINNED_TTL_S = 60;

/**
 * 解析 RELAY_DOMAINS（逗号分隔的域名后缀，小写归一）。
 * 空串/未设置 → 空数组（中继功能关闭）。
 */
export function parseRelayDomains(value: string | undefined): string[] {
  if (value === undefined || value.trim() === "") return [];
  const domains: string[] = [];
  for (const raw of value.split(",")) {
    const domain = raw.trim().toLowerCase().replace(/\.$/, "");
    if (domain === "") continue;
    if (!/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$/.test(domain)) {
      throw new Error("invalid_relay_domain");
    }
    domains.push(domain);
  }
  return domains;
}

/** 查询名是否命中中继域（完全相等或为其子域）。 */
export function matchRelayDomain(
  relayDomains: readonly string[],
  name: string | null
): string | null {
  if (name === null) return null;
  const normalized = name.toLowerCase();
  for (const domain of relayDomains) {
    if (normalized === domain || normalized.endsWith(`.${domain}`)) return domain;
  }
  return null;
}

/** 响应公共头：QR+RA+沿用查询 RD，qdcount=1。 */
function relayHeader(parsed: DnsMessageInfo, answerCount: number): Uint8Array {
  const header = new Uint8Array(12);
  writeU16(header, 0, parsed.id);
  writeU16(header, 2, (parsed.flags & 0x0100) | 0x8180); // QR|RA + 保留 RD
  writeU16(header, 4, 1);
  writeU16(header, 6, answerCount);
  return header;
}

/** 问题段原样复制（保留查询方自己的压缩/编码），答案名用 0xc00c 指回。 */
function withQuestion(query: Uint8Array, parsed: DnsMessageInfo, rrs: Uint8Array[]): Uint8Array {
  return concatBytes([relayHeader(parsed, rrs.length), query.slice(12, parsed.question.endOffset), ...rrs]);
}

function rrHead(rtype: number, rdataLength: number, ttl: number): Uint8Array {
  const head = new Uint8Array(12); // 名字(2) + type(2) + class(2) + ttl(4) + rdlength(2)
  head[0] = 0xc0;
  head[1] = 0x0c;
  writeU16(head, 2, rtype);
  writeU16(head, 4, 1); // IN
  writeU32(head, 6, ttl);
  writeU16(head, 10, rdataLength);
  return head;
}

/** A 查询 → 只回中继 IPv4（不回任何 CDN 地址，避免绕过中继）。 */
export function buildRelayAAnswer(
  query: Uint8Array,
  parsed: DnsMessageInfo,
  relayIpv4: Uint8Array
): Uint8Array {
  const rr = concatBytes([rrHead(TYPE_A, 4, RELAY_TTL_S), relayIpv4]);
  return withQuestion(query, parsed, [rr]);
}

/** A 查询 → 钉到给定地址列表（双 CDN 站统指：每地址一条 RR）。 */
export function buildPinnedAAnswer(
  query: Uint8Array,
  parsed: DnsMessageInfo,
  addresses: readonly Uint8Array[]
): Uint8Array {
  const rrs = addresses.map((address) => concatBytes([rrHead(TYPE_A, 4, PINNED_TTL_S), address]));
  return withQuestion(query, parsed, rrs);
}

/** AAAA 查询 → NOERROR 零答案（中继不开放 IPv6，回空防直连绕过）。 */
export function buildRelayEmptyAnswer(query: Uint8Array, parsed: DnsMessageInfo): Uint8Array {
  return withQuestion(query, parsed, []);
}

/**
 * HTTPS(65) 查询 → 合成 ServiceMode 记录：alpn=h2 + ech=共享公钥。
 * 故意不带 ipv4hint/ipv6hint（地址由 A 查询给中继 IP）也不带 port；
 * 中继只转发 TCP，不承诺 h3。
 */
export function buildRelayHttpsAnswer(
  query: Uint8Array,
  parsed: DnsMessageInfo,
  echValue: Uint8Array
): Uint8Array {
  const alpnValue = new Uint8Array([0x02, 0x68, 0x32]); // \x02h2
  const rdata = concatBytes([
    new Uint8Array([0, 1, 0]), // priority=1 + target=.
    writeParam(SVCB_ALPN_KEY, alpnValue),
    writeParam(SVCB_ECH_KEY, echValue)
  ]);
  const rr = concatBytes([rrHead(HTTPS_TYPE, rdata.length, RELAY_TTL_S), rdata]);
  return withQuestion(query, parsed, [rr]);
}

function writeParam(key: number, value: Uint8Array): Uint8Array {
  const param = new Uint8Array(4 + value.length);
  writeU16(param, 0, key);
  writeU16(param, 2, value.length);
  param.set(value, 4);
  return param;
}
