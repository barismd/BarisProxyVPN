#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import os
import re
import shutil
import sys
from urllib.parse import urlparse, parse_qs

import requests

SOURCE_URLS = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt",
]

OUTPUT_ALL = "all_sub.txt"
SPLIT_DIR = "splitted"
SPLIT_SIZE = 500

CONFIG_RE = re.compile(
    r'^(vmess|vless|trojan|ss|ssr|hy2|hysteria2|hysteria)://',
    re.IGNORECASE,
)


# ---------- fetch / decode ----------

def fetch(url):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[HATA] {url} -> {e}", file=sys.stderr)
        return ""


def try_b64(text):
    text = text.strip()
    if not text:
        return None
    pad = (-len(text)) % 4
    try:
        return base64.b64decode(text + "=" * pad).decode("utf-8", errors="ignore")
    except Exception:
        return None


def decode_if_b64(text):
    text = text.strip()
    if not text:
        return text
    compact = re.sub(r'\s+', '', text)
    if re.fullmatch(r'[A-Za-z0-9+/=_-]+', compact) and len(compact) > 40:
        d1 = try_b64(compact)
        if d1 and ('://' in d1 or '\n' in d1):
            d2 = try_b64(d1)
            if d2 and '://' in d2 and '://' not in d1:
                return d2
            return d1
    return text


def extract_configs(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if CONFIG_RE.match(line):
            out.append(line)
    return out


# ---------- port ----------

def get_port(cfg):
    try:
        low = cfg.lower()
        if low.startswith("vmess://"):
            b64 = cfg[8:]
            pad = (-len(b64)) % 4
            data = json.loads(base64.b64decode(b64 + "=" * pad).decode("utf-8", errors="ignore"))
            p = data.get("port")
            return int(p) if p is not None else None
        parsed = urlparse(cfg)
        if parsed.port:
            return parsed.port
        qs = parse_qs(parsed.query)
        if "port" in qs:
            return int(qs["port"][0])
    except Exception:
        pass
    return None


# ---------- dedup ----------

def normalize(cfg):
    return cfg.split("#", 1)[0].strip().lower()


def dedup(configs):
    seen = set()
    out = []
    for c in configs:
        k = normalize(c)
        if k and k not in seen:
            seen.add(k)
            out.append(c)
    return out


# ---------- split ----------

def split_and_write(configs, out_dir, size):
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    if not configs:
        print("[BİLGİ] Bölünecek config yok", flush=True)
        return 0

    chunks = [configs[i:i + size] for i in range(0, len(configs), size)]
    for idx, chunk in enumerate(chunks, 1):
        path = os.path.join(out_dir, f"sub{idx}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(chunk) + "\n")
    print(f"[BİLGİ] {len(chunks)} parça yazıldı ({out_dir}/sub1..sub{len(chunks)}.txt)", flush=True)
    return len(chunks)


# ---------- main ----------

def main():
    all_cfgs = []
    for url in SOURCE_URLS:
        print(f"[BİLGİ] İndiriliyor: {url}", flush=True)
        raw = fetch(url)
        if not raw:
            continue
        decoded = decode_if_b64(raw)
        cfgs = extract_configs(decoded)
        print(f"[BİLGİ] {len(cfgs)} config bulundu", flush=True)
        all_cfgs.extend(cfgs)

    print(f"[BİLGİ] Toplam ham: {len(all_cfgs)}", flush=True)

    # port filtresi (80 / 443)
    filtered = [c for c in all_cfgs if get_port(c) in (80, 443)]
    print(f"[BİLGİ] Port filtresi sonrası: {len(filtered)}", flush=True)

    # dedup
    unique = dedup(filtered)
    print(f"[BİLGİ] Dedup sonrası: {len(unique)}", flush=True)

    # all_sub.txt
    with open(OUTPUT_ALL, "w", encoding="utf-8") as f:
        f.write("\n".join(unique) + ("\n" if unique else ""))
    print(f"[BİLGİ] {OUTPUT_ALL} yazıldı ({len(unique)} satır)", flush=True)

    # splitted/
    split_and_write(unique, SPLIT_DIR, SPLIT_SIZE)


if __name__ == "__main__":
    main()
