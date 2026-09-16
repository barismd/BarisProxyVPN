#!/usr/bin/env python3
"""
V2ray config aggregator.

- Downloads config lists from SOURCE_URLS (always fresh, no local caching).
- Keeps only configs whose port is 443 or 80.
- De-duplicates by the actual connection info (ignores the #remark/name part
  of the URI), so two entries with different names but the same connection
  are treated as duplicates and only one is kept.
- Writes the de-duplicated result to sub.txt.
- TCP-tests each remaining config's host:port and writes only the ones that
  pass to supersub.txt.
"""

import base64
import binascii
import json
import socket
import time
import concurrent.futures
from urllib.parse import urlparse, parse_qsl
import requests

SOURCE_URLS = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
]

ALLOWED_PORTS = {80, 443}
SUB_FILE = "sub.txt"
SUPERSUB_FILE = "supersub.txt"
CONNECT_TIMEOUT = 5      # seconds, per TCP test
MAX_WORKERS = 50         # parallel TCP tests


def b64_decode(data: str) -> str:
    """Base64 decode that tolerates missing padding and url-safe variants."""
    data = data.strip()
    data += "=" * (-len(data) % 4)
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError):
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")


def fetch(url: str) -> str:
    """Always download fresh content, bypassing any CDN/proxy caching."""
    headers = {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "User-Agent": "Mozilla/5.0 (config-fetcher)",
    }
    bust = f"{'&' if '?' in url else '?'}_cb={int(time.time())}"
    resp = requests.get(url + bust, headers=headers, timeout=20)
    resp.raise_for_status()
    return resp.text


def split_lines(raw: str):
    """Return a clean list of non-empty config lines from a source file's raw
    text. Some subscription files store the whole list as one base64 blob;
    handle both cases."""
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if any("://" in ln for ln in lines):
        return lines
    try:
        decoded = b64_decode(raw)
        return [ln.strip() for ln in decoded.splitlines() if ln.strip()]
    except Exception:
        return lines


def parse_config(line: str):
    """
    Parse a single config URI.

    Returns dict {scheme, host, port, key} on success, or None if the line
    can't be parsed. 'key' is a canonical string used for de-duplication
    that ignores the remark/name (#...) part of the URI.
    """
    try:
        if "#" in line:
            base, _remark = line.split("#", 1)
        else:
            base, _remark = line, ""

        if "://" not in base:
            return None
        scheme = base.split("://", 1)[0].lower()

        if scheme == "vmess":
            payload = base[len("vmess://"):]
            decoded = b64_decode(payload)
            data = json.loads(decoded)
            host = str(data.get("add", "")).strip()
            port = int(str(data.get("port", "0")).strip())
            data.pop("ps", None)  # remove remark from the dedup key
            key = "vmess://" + json.dumps(data, sort_keys=True)
            return {"scheme": scheme, "host": host, "port": port, "key": key}

        if scheme == "ss":
            rest = base[len("ss://"):]
            main_part, _, query = rest.partition("?")
            if "@" in main_part:
                userinfo, hostport = main_part.rsplit("@", 1)
            else:
                decoded = b64_decode(main_part)
                userinfo, hostport = decoded.rsplit("@", 1)
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s.strip("/"))
            key = f"ss://{userinfo}@{host}:{port}?{query}"
            return {"scheme": scheme, "host": host, "port": port, "key": key}

        if scheme == "ssr":
            payload = base[len("ssr://"):]
            decoded = b64_decode(payload)
            main_part, _, params = decoded.partition("/?")
            fields = main_part.split(":")
            if len(fields) < 6:
                return None
            host, port_s = fields[0], fields[1]
            port = int(port_s)
            kept = [kv for kv in params.split("&") if kv and not kv.startswith("remarks=")]
            key = "ssr://" + ":".join(fields) + "/?" + "&".join(sorted(kept))
            return {"scheme": scheme, "host": host, "port": port, "key": key}

        # vless, trojan, hysteria, hysteria2, hy2, tuic, and similar schemes
        parsed = urlparse(base)
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None
        params = sorted(parse_qsl(parsed.query))
        key = f"{scheme}://{parsed.username or ''}@{host}:{port}?{params}"
        return {"scheme": scheme, "host": host, "port": int(port), "key": key}

    except Exception:
        return None


def build_sub():
    seen = {}
    ordered_entries = []
    for url in SOURCE_URLS:
        try:
            raw = fetch(url)
        except Exception as e:
            print(f"[warn] could not fetch {url}: {e}")
            continue
        for line in split_lines(raw):
            info = parse_config(line)
            if not info:
                continue
            if info["port"] not in ALLOWED_PORTS:
                continue
            if info["key"] in seen:
                continue
            seen[info["key"]] = True
            ordered_entries.append((line, info["host"], info["port"]))

    with open(SUB_FILE, "w", encoding="utf-8") as f:
        if ordered_entries:
            f.write("\n".join(line for line, _, _ in ordered_entries) + "\n")

    print(f"[info] {SUB_FILE}: {len(ordered_entries)} unique configs (port 80/443)")
    return ordered_entries


def tcp_test(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except Exception:
        return False


def build_supersub(entries):
    passed = []

    def worker(item):
        line, host, port = item
        return line if tcp_test(host, port) else None

    if entries:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            for result in pool.map(worker, entries):
                if result:
                    passed.append(result)

    with open(SUPERSUB_FILE, "w", encoding="utf-8") as f:
        if passed:
            f.write("\n".join(passed) + "\n")

    print(f"[info] {SUPERSUB_FILE}: {len(passed)}/{len(entries)} configs passed the connection test")


if __name__ == "__main__":
    sub_entries = build_sub()
    build_supersub(sub_entries)
