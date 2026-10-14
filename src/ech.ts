import { concatBytes, readU16, writeU16 } from "./binary";
import { parseName, type DnsMessageInfo } from "./dns";

export const SVCB_ALPN_KEY = 1;
export const SVCB_ECH_KEY = 5;
export const SVCB_IPV4HINT_KEY = 4;
export const HTTPS_TYPE = 65;
export const TYPE_A = 1;
export const TYPE_AAAA = 28;

/**
 * 扫描 SVCB/HTTPS rdata 的参数区（priority(2) + target(name) + (key(2)+len(2)+value)*），
 * 取出 ech（SvcParamKey=5）的值。截断/畸形一律安全返回 null。
 */
export function svcbGetEch(data: Uint8Array, start: number, end: number): Uint8Array | null {
  for (const param of iterateSvcbParams(data, start, end)) {
    if (param.key === SVCB_ECH_KEY) return data.slice(param.valueStart, param.valueEnd);
  }
  return null;
}

export function svcbHasEch(data: Uint8Array, start: number, end: number): boolean {
  return svcbGetEch(data, start, end) !== null;
}

/** 取 ipv4hint（key=4）里列出的全部 IPv4（每个 4 字节）。 */
export function svcbIpv4Hints(data: Uint8Array, start: number, end: number): Uint8Array[] {
  const hints: Uint8Array[] = [];
  for (const param of iterateSvcbParams(data, start, end)) {
    if (param.key !== SVCB_IPV4HINT_KEY) continue;
    for (let p = param.valueStart; p + 4 <= param.valueEnd; p += 4) {
      hints.push(data.slice(p, p + 4));
    }
  }
  return hints;
}

/** ServiceMode（priority > 0）才允许携带参数；AliasMode 的参数区必须为空。 */
export function svcbIsServiceMode(data: Uint8Array, start: number, end: number): boolean {
  if (start + 2 > end) return false;
  return readU16(data, start) > 0;
}

interface SvcParam {
  key: number;
  valueStart: number;
  valueEnd: number;
}

function* iterateSvcbParams(
  data: Uint8Array,
  start: number,
  end: number
): Generator<SvcParam> {
  if (start + 2 > end) return;
  let cursor = start + 2; // 跳过 priority
  try {
    const target = parseName(data, cursor);
    cursor = target.nextOffset;
  } catch {
    return;
  }
  while (cursor + 4 <= end) {
    const key = readU16(data, cursor);
    const length = readU16(data, cursor + 2);
    if (cursor + 4 + length > end) return;
    yield { key, valueStart: cursor + 4, valueEnd: cursor + 4 + length };
    cursor += 4 + length;
  }
}

// Cloudflare 官方公布的 IPv4 网段（https://www.cloudflare.com/ips-v4）。
const CLOUDFLARE_V4_RANGES: ReadonlyArray<readonly [number, number]> = ([
  [0xadf53000, 0xfffff000], // 173.245.48.0/20
  [0x6715f400, 0xfffffffc], // 103.21.244.0/22
  [0x6716c800, 0xfffffffc], // 103.22.200.0/22
  [0x671f0400, 0xfffffffc], // 103.31.4.0/22
  [0x8d654000, 0xffffffc0], // 141.101.64.0/18
  [0x6ca2c000, 0xffffffc0], // 108.162.192.0/18
  [0xbe5df000, 0xfffff000], // 190.93.240.0/20
  [0xbc726000, 0xfffff000], // 188.114.96.0/20
  [0xc5eaf000, 0xfffffffc], // 197.234.240.0/22
  [0xc6298000, 0xffff8000], // 198.41.128.0/17
  [0xa29e0000, 0xfffe0000], // 162.158.0.0/15
  [0x68100000, 0xfff80000], // 104.16.0.0/13
  [0x68180000, 0xfffc0000], // 104.24.0.0/14
  [0xac400000, 0xfff80000] // 172.64.0.0/13
] as ReadonlyArray<readonly [number, number]>).map(
  ([base, mask]) => [base >>> 0, mask >>> 0] as const
);

function ipv4ToU32(ip: Uint8Array): number {
  return (((ip[0] ?? 0) << 24) | ((ip[1] ?? 0) << 16) | ((ip[2] ?? 0) << 8) | (ip[3] ?? 0)) >>> 0;
}

export function isCloudflareIPv4(ip: Uint8Array): boolean {
  if (ip.length !== 4) return false;
  const value = ipv4ToU32(ip);
  return CLOUDFLARE_V4_RANGES.some(([base, mask]) => (value & mask) === base);
}

/**
 * 判断 HTTPS 答案是否可确认托管在 Cloudflare：至少一条记录带 ipv4hint，
 * 且所有 hint 都落在 CF 网段。没有 hint 的记录无法证实，视为不满足。
 */
export function httpsHintsAllCloudflare(body: Uint8Array, info: DnsMessageInfo): boolean {
  let checked = 0;
  for (const record of info.answers) {
    if (record.type !== HTTPS_TYPE) continue;
    if (!svcbIsServiceMode(body, record.rdataStart, record.rdataEnd)) continue;
    const hints = svcbIpv4Hints(body, record.rdataStart, record.rdataEnd);
    if (hints.length === 0) continue;
    if (!hints.every(isCloudflareIPv4)) return false;
    checked += 1;
  }
  return checked > 0;
}

/**
 * 把共享 ech 参数拼进答案里所有缺 ech 的 ServiceMode HTTPS 记录（更新 rdlength）。
 * 从后往前插，避免前面的插入让后续记录的偏移失效；压缩指针只指向前方，
 * 不受影响。没有可插的记录时返回 null。
 */
export function spliceEchIntoAnswers(
  body: Uint8Array,
  info: DnsMessageInfo,
  echValue: Uint8Array
): Uint8Array | null {
  const targets = info.answers.filter(
    (record) =>
      record.type === HTTPS_TYPE &&
      !svcbHasEch(body, record.rdataStart, record.rdataEnd) &&
      svcbIsServiceMode(body, record.rdataStart, record.rdataEnd)
  );
  if (targets.length === 0) return null;
  let output = body;
  for (const record of [...targets].sort((a, b) => b.rdataStart - a.rdataStart)) {
    const param = new Uint8Array(4 + echValue.length);
    writeU16(param, 0, SVCB_ECH_KEY);
    writeU16(param, 2, echValue.length);
    param.set(echValue, 4);
    const rdataLength = record.rdataEnd - record.rdataStart;
    output = concatBytes([
      output.slice(0, record.rdataEnd),
      param,
      output.slice(record.rdataEnd)
    ]);
    writeU16(output, record.rdataStart - 2, rdataLength + param.length);
  }
  return output;
}

/** 答案里是否存在至少一条 HTTPS 记录。 */
export function hasHttpsAnswer(info: DnsMessageInfo): boolean {
  return info.answers.some((record) => record.type === HTTPS_TYPE);
}

/** 答案里第一条带 ech 的 HTTPS 记录的 ech 值（共享公钥引导用）。 */
export function firstEchValue(body: Uint8Array, info: DnsMessageInfo): Uint8Array | null {
  for (const record of info.answers) {
    if (record.type !== HTTPS_TYPE) continue;
    const value = svcbGetEch(body, record.rdataStart, record.rdataEnd);
    if (value !== null && value.length > 0) return value;
  }
  return null;
}

/** 构造标准递归查询报文（header + qname + qtype/qclass，无 OPT）。 */
export function buildQuery(name: string, qtype: number, id = 0x1234): Uint8Array {
  const labels = name.split(".");
  const parts: Uint8Array[] = [];
  const header = new Uint8Array(12);
  writeU16(header, 0, id);
  writeU16(header, 2, 0x0100); // RD
  writeU16(header, 4, 1);
  parts.push(header);
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) throw new Error("invalid_qname_label");
    parts.push(new Uint8Array([label.length, ...new TextEncoder().encode(label)]));
  }
  parts.push(new Uint8Array([0]));
  const tail = new Uint8Array(4);
  writeU16(tail, 0, qtype);
  writeU16(tail, 2, 1);
  parts.push(tail);
  return concatBytes(parts);
}
