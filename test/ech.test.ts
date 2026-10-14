import { describe, expect, it } from "vitest";
import { svcbHasEch } from "../src/ech";
import { parseDnsMessage } from "../src/dns";
import { concatBytes, writeU16 } from "../src/binary";

/** 构造最小 SVCB/HTTPS rdata：priority + target(根) + 参数列表。 */
function svcbRdata(params: Array<{ key: number; value: Uint8Array }>): Uint8Array {
  const parts: Uint8Array[] = [];
  const priority = new Uint8Array([0, 1]);
  const root = new Uint8Array([0]); // target = .
  parts.push(priority, root);
  for (const p of params) {
    const item = new Uint8Array(4 + p.value.length);
    item[0] = p.key >> 8;
    item[1] = p.key & 0xff;
    item[2] = p.value.length >> 8;
    item[3] = p.value.length & 0xff;
    item.set(p.value, 4);
    parts.push(item);
  }
  return concatBytes(parts);
}

describe("svcbHasEch", () => {
  it("检测到 ech(5) 参数返回 true", () => {
    const rdata = svcbRdata([
      { key: 1, value: new Uint8Array([2, 104, 50]) }, // alpn=h2
      { key: 5, value: new Uint8Array([0x10, 0x20, 0x30]) } // ech
    ]);
    expect(svcbHasEch(rdata, 0, rdata.length)).toBe(true);
  });

  it("无 ech 参数返回 false", () => {
    const rdata = svcbRdata([
      { key: 1, value: new Uint8Array([2, 104, 50]) },
      { key: 4, value: new Uint8Array(4) } // ipv4hint
    ]);
    expect(svcbHasEch(rdata, 0, rdata.length)).toBe(false);
  });

  it("截断的参数区安全返回 false", () => {
    const rdata = svcbRdata([{ key: 5, value: new Uint8Array(4) }]);
    // 长度字段（第 5-6 字节）声称 8 字节但数据只剩 4 字节
    rdata[5] = 0;
    rdata[6] = 8;
    expect(svcbHasEch(rdata, 0, rdata.length)).toBe(false);
  });

  it("空 rdata 返回 false", () => {
    expect(svcbHasEch(new Uint8Array(2), 0, 2)).toBe(false);
  });
});

/** 构造完整 DNS 应答（1 个 HTTPS answer），返回 wireformat。 */
function httpsAnswer(rdata: Uint8Array): Uint8Array {
  const header = new Uint8Array(12);
  header[2] = 0x81; header[3] = 0x80; // flags: QR+RA
  header[5] = 1; // qdcount=1
  header[7] = 1; // ancount=1
  // qname = x.com → [1,'x',3,'c','o','m',0]
  const qname = new Uint8Array([1, 0x78, 3, 0x63, 0x6f, 0x6d, 0]);
  const question = concatBytes([qname, new Uint8Array([0, 65, 0, 1])]);
  const namePtr = new Uint8Array([0xc0, 12]);
  const rrHead = new Uint8Array([0, 65, 0, 1, 0, 0, 0, 60, 0, 0]);
  rrHead[8] = rdata.length >> 8;
  rrHead[9] = rdata.length & 0xff;
  return concatBytes([header, question, namePtr, rrHead, rdata]);
}

describe("HTTPS 应答解析", () => {
  it("答案带 ech 时 parseDnsMessage + svcbHasEch 可检出", () => {
    const body = httpsAnswer(svcbRdata([{ key: 5, value: new Uint8Array([1, 2, 3, 4]) }]));
    const info = parseDnsMessage(body);
    expect(info.answers[0]!.type).toBe(65);
    const r = info.answers[0]!;
    expect(svcbHasEch(body, r.rdataStart, r.rdataEnd)).toBe(true);
  });

  it("答案无 ech 时判定为 false", () => {
    const body = httpsAnswer(svcbRdata([{ key: 1, value: new Uint8Array([2, 104, 50]) }]));
    const info = parseDnsMessage(body);
    const r = info.answers[0]!;
    expect(svcbHasEch(body, r.rdataStart, r.rdataEnd)).toBe(false);
  });
});

describe("writeU16 往返", () => {
  it("大端写入可读回", () => {
    const buf = new Uint8Array(2);
    writeU16(buf, 0, 0x1234);
    expect(buf[0]).toBe(0x12);
    expect(buf[1]).toBe(0x34);
  });
});
