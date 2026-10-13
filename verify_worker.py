#!/usr/bin/env python3
"""验证 muse-upgrade Worker：ECS 是否只发 CF、回的 CDN 是否就近。

用法：
  1. 终端 A：wrangler dev --port 8787        # 本地起 Worker（空 KV 也行）
  2. 终端 B：python3 verify-worker.py [--doh http://127.0.0.1:8787/doh]

原理：
  - 用 POST wireformat 查 youtube.com / github.com（mihomo 同款形状）
  - 抓回包 A 记录，用 ip-api.com 判归属地（近=HK/JP/SG/KR，远=US）
  - 再查一次同域名：命中缓存应毫秒级且答案一致
  - 打印 Worker 的 doh_upstream_failed 日志需另看终端 A
"""
import argparse
import base64
import json
import struct
import sys
import time
import urllib.request

DOMAINS = ["www.youtube.com", "github.com"]

# 抓包确认 ECS 是否被带上：直接问 Worker 是看不到的，这里用“答案归属地”
# 反推 —— CF 拿到 ECS 回近节点、拿不到回美国节点。
NEAR = {"HK", "JP", "SG", "KR", "TW", "CN"}


def build_query(name, qtype=1, txid=0x1234):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    hdr = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return hdr + labels + b"\x00" + struct.pack(">HH", qtype, 1)


def parse_answers(body):
    """粗解析：返回 [(type, ttl, rdata_str)]。只处理 A 记录。"""
    qdcount = struct.unpack(">H", body[4:6])[0]
    off = 12
    for _ in range(qdcount):
        while True:
            ln = body[off]
            if ln >= 0xC0:
                off += 2
                break
            off += 1
            if ln == 0:
                break
            off += ln
        off += 4  # qtype + qclass
    ancount = struct.unpack(">H", body[6:8])[0]
    out = []
    for _ in range(ancount):
        if body[off] >= 0xC0:
            off += 2
        else:
            while body[off] != 0:
                off += 1 + body[off]
            off += 1
        rtype, _, ttl, rdlen = struct.unpack(">HHIH", body[off:off + 10])
        rdata = body[off + 10:off + 10 + rdlen]
        off += 10 + rdlen
        if rtype == 1 and len(rdata) == 4:
            out.append((rtype, ttl, ".".join(map(str, rdata))))
    return out


_PROXY = None  # 全局：--proxy 传入后所有请求（含 geo）都走它


def _opener():
    if _PROXY is None:
        return urllib.request.build_opener()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": _PROXY, "https": _PROXY}))


def doh_post(doh, query, timeout=15):
    req = urllib.request.Request(
        doh, data=query,
        headers={"Content-Type": "application/dns-message",
                 "Accept": "application/dns-message",
                 # workers.dev 会拦 Python-urllib 默认 UA，伪装成常规客户端
                 "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) clash-verge/2.3.3"},
        method="POST")
    t0 = time.monotonic()
    with _opener().open(req, timeout=timeout) as r:
        body = r.read()
    return body, (time.monotonic() - t0) * 1000


def geo(ip):
    try:
        with _opener().open(f"http://ip-api.com/json/{ip}?fields=countryCode,org",
                            timeout=10) as r:
            return json.load(r)
    except Exception as e:
        return {"countryCode": "?", "org": f"geo-fail:{e}"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--doh", default="http://127.0.0.1:8787/doh")
    ap.add_argument("--no-geo", action="store_true", help="跳过归属地查询（无 TUN 直连时 ip-api 可能够不着）")
    ap.add_argument("--proxy", default=None,
                    help="经 mihomo 代理访问 DoH，如 http://127.0.0.1:7897（本地 DNS 被 fake-ip 接管时用）")
    args = ap.parse_args()
    global _PROXY
    _PROXY = args.proxy

    ok = True
    for name in DOMAINS:
        print(f"== {name} ==")
        try:
            body1, ms1 = doh_post(args.doh, build_query(name))
        except Exception as e:
            print(f"  FAIL 出错: {e}")
            ok = False
            continue
        rcode = body1[3] & 0x0F
        ans = parse_answers(body1)
        print(f"  首次: {ms1:.0f}ms rcode={rcode} A={ans}")
        if rcode != 0 or not ans:
            print("  FAIL 无有效答案")
            ok = False
            continue
        # 第二次：应命中缓存（毫秒级）
        body2, ms2 = doh_post(args.doh, build_query(name, txid=0x5678))
        ans2 = parse_answers(body2)
        txid2 = struct.unpack(">H", body2[0:2])[0]
        cached = ms2 < 200 and ans2 == ans and txid2 == 0x5678
        print(f"  二次: {ms2:.0f}ms txid回写={'ok' if txid2 == 0x5678 else 'BAD'} "
              f"答案一致={'ok' if ans2 == ans else 'BAD'} 缓存={'HIT' if cached else 'MISS?'}")
        for _, ttl, ip in ans:
            if args.no_geo:
                print(f"    {ip} ttl={ttl}")
                continue
            g = geo(ip)
            cc = g.get("countryCode", "?")
            tag = "近" if cc in NEAR else ("远" if cc == "US" else "?")
            print(f"    {ip} ttl={ttl} {cc} {g.get('org', '')} [{tag}]")
            if cc == "US":
                print("    提示: 回美国节点 —— 可能 ECS 没带上，或你开着 TUN（落地即美国）")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
