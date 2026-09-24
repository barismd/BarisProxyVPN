#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote

import requests

# ---------- Kaynaklar ----------
SOURCE_URLS = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt",
]

OUTPUT_ALL = "all_sub.txt"
OUTPUT_SUPERS = "supersub.txt"
SPLIT_DIR = "splitted"
SPLIT_SIZE = 500

XRAY_PATH = os.environ.get("XRAY_PATH", "./xray-core/xray")
SOCKS_PORT = 10808
TEST_URL = "http://www.gstatic.com/generate_204"
TUNNEL_TIMEOUT = 6
SERVER_TIMEOUT = 3
SERVER_WORKERS = 50
TUNNEL_WORKERS = 20

CONFIG_RE = re.compile(
    r'^(vmess|vless|trojan|ss|ssr|hy2|hysteria2|hysteria)://',
    re.IGNORECASE,
)


# =====================================================================
#  FETCH / DECODE / EXTRACT
# =====================================================================

def fetch(url):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[HATA] {url} -> {e}", file=sys.stderr, flush=True)
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


# =====================================================================
#  PORT
# =====================================================================

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


# =====================================================================
#  NORMALIZE (güçlendirildi) + DEDUP
# =====================================================================

def normalize(cfg):
    c = cfg.split("#", 1)[0].strip()
    low = c.lower()

    if low.startswith("vmess://"):
        try:
            b64 = c[8:]
            pad = (-len(b64)) % 4
            d = json.loads(base64.b64decode(b64 + "=" * pad).decode("utf-8", errors="ignore"))

            if "port" in d:
                try:
                    d["port"] = int(d["port"])
                except Exception:
                    pass

            for k in ("add", "host", "sni", "net", "type", "tls", "scy"):
                if k in d and isinstance(d[k], str):
                    d[k] = d[k].strip().lower()

            if "path" in d and isinstance(d["path"], str):
                d["path"] = d["path"].strip()

            d = {k: v for k, v in d.items() if v not in ("", None)}

            return "vmess://" + json.dumps(d, sort_keys=True, separators=(",", ":"))
        except Exception:
            return low

    try:
        p = urlparse(c)
        if not p.hostname:
            return low

        q = parse_qs(p.query, keep_blank_values=True)
        items = []
        for k in sorted(q.keys()):
            vals = q[k] or [""]
            for v in vals:
                items.append((k.lower(), v))
        q_str = "&".join(f"{k}={v}" for k, v in items)

        user = (p.username or "")
        host = p.hostname.lower()
        port = p.port or 0
        scheme = p.scheme.lower()

        if scheme == "ss":
            netloc = (p.netloc or "").lower()
            return f"{scheme}://{netloc}?{q_str}"

        return f"{scheme}://{user}@{host}:{port}?{q_str}"
    except Exception:
        return low


def dedup(configs):
    seen = set()
    out = []
    for c in configs:
        k = normalize(c)
        if k and k not in seen:
            seen.add(k)
            out.append(c)
    return out


# =====================================================================
#  SERVER TEST  (TCP reachability, lenient)
# =====================================================================

def parse_uri_info(uri):
    low = uri.lower()
    try:
        if low.startswith("vmess://"):
            b64 = uri[8:]
            pad = (-len(b64)) % 4
            d = json.loads(base64.b64decode(b64 + "=" * pad).decode("utf-8", errors="ignore"))
            host = d.get("add")
            if not host:
                return None
            port = int(d.get("port", 443))
            sni = d.get("sni") or d.get("host") or host
            security = (d.get("tls") or "none").lower()
            return host, port, sni, security

        if low.startswith("ss://"):
            body = uri[5:]
            if "#" in body:
                body = body.split("#", 1)[0]
            if "?" in body:
                body = body.split("?", 1)[0]
            if "@" not in body:
                pad = (-len(body)) % 4
                body = base64.b64decode(body + "=" * pad).decode("utf-8", errors="ignore")
            userinfo, hostport = body.rsplit("@", 1)
            host, port = hostport.rsplit(":", 1)
            return host, int(port), host, "none"

        p = urlparse(uri)
        if not p.hostname:
            return None
        qs = parse_qs(p.query)
        sni = (qs.get("sni") or qs.get("host") or [p.hostname])[0]
        security = (qs.get("security") or ["none"])[0].lower()
        return p.hostname, (p.port or 443), sni, security
    except Exception:
        return None


def test_server(uri, timeout=SERVER_TIMEOUT):
    info = parse_uri_info(uri)
    if not info:
        return False, "parse-fail"
    host, port, sni, security = info
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True, "tcp-ok"
    except Exception:
        return False, "tcp-fail"


# =====================================================================
#  OUTBOUND BUILDERS  (tunnel test için)
# =====================================================================

def _p(params, key, default=None):
    return params.get(key, [default])[0]


def build_vmess(uri):
    b64 = uri[8:]
    pad = (-len(b64)) % 4
    d = json.loads(base64.b64decode(b64 + "=" * pad).decode("utf-8", errors="ignore"))

    net = (d.get("net") or "tcp").lower()
    tls_field = (d.get("tls") or "").lower()
    host = d.get("host") or d.get("add") or ""
    path = d.get("path") or "/"
    sni = d.get("sni") or host

    stream = {"network": net}
    if tls_field == "tls":
        stream["security"] = "tls"
        ts = {"serverName": sni, "allowInsecure": False}
        if d.get("alpn"):
            ts["alpn"] = [a for a in d["alpn"].split(",") if a]
        if d.get("fp"):
            ts["fingerprint"] = d["fp"]
        stream["tlsSettings"] = ts
    else:
        stream["security"] = "none"

    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host} if host else {}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": path if path != "/" else ""}
    elif net in ("h2", "http"):
        stream["network"] = "h2"
        stream["httpSettings"] = {"path": path, "host": [host] if host else []}
    elif net == "tcp" and (d.get("type") or "").lower() == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [path],
                    "headers": {"Host": [host]} if host else {},
                },
            }
        }

    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": d["add"],
                "port": int(d["port"]),
                "users": [{
                    "id": d["id"],
                    "alterId": int(d.get("aid", 0) or 0),
                    "security": d.get("scy") or "auto",
                }],
            }]
        },
        "streamSettings": stream,
        "tag": "proxy",
    }


def build_vless(uri):
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    user = {
        "id": parsed.username or "",
        "encryption": _p(params, "encryption", "none") or "none",
    }
    flow = _p(params, "flow", "")
    if flow:
        user["flow"] = flow

    net = (_p(params, "type", "tcp") or "tcp").lower()
    security = (_p(params, "security", "none") or "none").lower()
    sni = _p(params, "sni") or _p(params, "host") or parsed.hostname or ""
    fp = _p(params, "fp")
    alpn = _p(params, "alpn")
    pbk = _p(params, "pbk")
    sid = _p(params, "sid", "") or ""
    spx = _p(params, "spx")
    path = unquote(_p(params, "path", "/") or "/")
    host = _p(params, "host") or sni
    service_name = _p(params, "serviceName", "") or ""

    stream = {"network": net, "security": security}

    if security == "tls":
        ts = {"serverName": sni, "allowInsecure": False}
        if fp:
            ts["fingerprint"] = fp
        if alpn:
            ts["alpn"] = [a for a in alpn.split(",") if a]
        stream["tlsSettings"] = ts
    elif security == "reality":
        rs = {"serverName": sni, "fingerprint": fp or "chrome"}
        if pbk:
            rs["publicKey"] = pbk
        if sid:
            rs["shortId"] = sid
        if spx:
            rs["spiderX"] = spx
        stream["realitySettings"] = rs

    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host} if host else {}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": service_name}
    elif net in ("h2", "http"):
        stream["network"] = "h2"
        stream["httpSettings"] = {"path": path, "host": [host] if host else []}
    elif net == "tcp" and (_p(params, "headerType", "") or "").lower() == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [path],
                    "headers": {"Host": [host]} if host else {},
                },
            }
        }

    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": parsed.hostname,
                "port": parsed.port or 443,
                "users": [user],
            }]
        },
        "streamSettings": stream,
        "tag": "proxy",
    }


def build_trojan(uri):
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    net = (_p(params, "type", "tcp") or "tcp").lower()
    security = (_p(params, "security", "tls") or "tls").lower()
    sni = _p(params, "sni") or _p(params, "host") or parsed.hostname or ""
    fp = _p(params, "fp")
    alpn = _p(params, "alpn")
    pbk = _p(params, "pbk")
    sid = _p(params, "sid", "") or ""
    spx = _p(params, "spx")
    path = unquote(_p(params, "path", "/") or "/")
    host = _p(params, "host") or sni
    service_name = _p(params, "serviceName", "") or ""

    stream = {"network": net, "security": security}

    if security == "tls":
        ts = {"serverName": sni, "allowInsecure": False}
        if fp:
            ts["fingerprint"] = fp
        if alpn:
            ts["alpn"] = [a for a in alpn.split(",") if a]
        stream["tlsSettings"] = ts
    elif security == "reality":
        rs = {"serverName": sni, "fingerprint": fp or "chrome"}
        if pbk:
            rs["publicKey"] = pbk
        if sid:
            rs["shortId"] = sid
        if spx:
            rs["spiderX"] = spx
        stream["realitySettings"] = rs

    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host} if host else {}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": service_name}
    elif net in ("h2", "http"):
        stream["network"] = "h2"
        stream["httpSettings"] = {"path": path, "host": [host] if host else []}
    elif net == "tcp" and (_p(params, "headerType", "") or "").lower() == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [path],
                    "headers": {"Host": [host]} if host else {},
                },
            }
        }

    return {
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": parsed.hostname,
                "port": parsed.port or 443,
                "password": unquote(parsed.username or ""),
            }]
        },
        "streamSettings": stream,
        "tag": "proxy",
    }


def build_ss(uri):
    body = uri[5:]
    if "#" in body:
        body, _ = body.split("#", 1)
    if "?" in body:
        body, _ = body.split("?", 1)
    if "@" not in body:
        pad = (-len(body)) % 4
        body = base64.b64decode(body + "=" * pad).decode("utf-8", errors="ignore")
    if "@" not in body:
        return None
    userinfo, hostport = body.rsplit("@", 1)
    if ":" not in userinfo:
        pad = (-len(userinfo)) % 4
        userinfo = base64.b64decode(userinfo + "=" * pad).decode("utf-8", errors="ignore")
    method, password = userinfo.split(":", 1)
    host, port = hostport.rsplit(":", 1)
    return {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": host,
                "port": int(port),
                "method": method,
                "password": password,
            }]
        },
        "streamSettings": {"network": "tcp", "security": "none"},
        "tag": "proxy",
    }


def build_outbound(uri):
    low = uri.lower()
    if low.startswith("vmess://"):
        return build_vmess(uri)
    if low.startswith("vless://"):
        return build_vless(uri)
    if low.startswith("trojan://"):
        return build_trojan(uri)
    if low.startswith("ss://"):
        return build_ss(uri)
    return None


# =====================================================================
#  TUNNEL TEST  (gerçek proxy trafiği)
# =====================================================================

def wait_port(host, port, proc, timeout=4.0):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            s = socket.create_connection((host, port), timeout=0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.15)
    return False


def test_tunnel(uri, xray_path):
    try:
        outbound = build_outbound(uri)
    except Exception:
        return False, "build-fail"
    if outbound is None:
        return False, "unsupported"

    config = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "port": SOCKS_PORT,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": False, "auth": "noauth"},
        }],
        "outbounds": [outbound],
    }

    fd, cfg_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(cfg_path, "w") as f:
        json.dump(config, f)

    proc = None
    try:
        proc = subprocess.Popen(
            [xray_path, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not wait_port("127.0.0.1", SOCKS_PORT, proc, timeout=4.0):
            return False, "xray-not-up"

        try:
            res = subprocess.run(
                [
                    "curl", "-s", "-o", "/dev/null",
                    "-w", "%{http_code}",
                    "--max-time", str(TUNNEL_TIMEOUT),
                    "--socks5-hostname", f"127.0.0.1:{SOCKS_PORT}",
                    TEST_URL,
                ],
                capture_output=True, text=True, timeout=TUNNEL_TIMEOUT + 3,
            )
            code = res.stdout.strip()
            return (code in ("200", "204", "301", "302")), code or "empty"
        except subprocess.TimeoutExpired:
            return False, "timeout"
    except Exception as e:
        return False, f"err:{type(e).__name__}"
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


# =====================================================================
#  SPLIT
# =====================================================================

def split_and_write(configs, out_dir, size):
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    if not configs:
        return 0
    chunks = [configs[i:i + size] for i in range(0, len(configs), size)]
    for idx, chunk in enumerate(chunks, 1):
        with open(os.path.join(out_dir, f"sub{idx}.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(chunk) + "\n")
    print(f"[BİLGİ] {len(chunks)} parça yazıldı -> {out_dir}/", flush=True)
    return len(chunks)


# =====================================================================
#  MAIN
# =====================================================================

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

    filtered = [c for c in all_cfgs if get_port(c) in (80, 443)]
    print(f"[BİLGİ] Port filtresi (80/443) sonrası: {len(filtered)}", flush=True)

    unique = dedup(filtered)
    print(f"[BİLGİ] Dedup sonrası: {len(unique)}", flush=True)

    with open(OUTPUT_ALL, "w", encoding="utf-8") as f:
        f.write("\n".join(unique) + ("\n" if unique else ""))
    print(f"[BİLGİ] {OUTPUT_ALL} yazıldı", flush=True)

    split_and_write(unique, SPLIT_DIR, SPLIT_SIZE)

    # ---------- SERVER TEST ----------
    print(f"[BİLGİ] Server testi başlıyor ({len(unique)} config)...", flush=True)
    server_pass = []
    done = 0
    with ThreadPoolExecutor(max_workers=SERVER_WORKERS) as ex:
        futures = {ex.submit(test_server, c): c for c in unique}
        for fut in as_completed(futures):
            c = futures[fut]
            done += 1
            try:
                ok, _ = fut.result()
            except Exception:
                ok = False
            if ok:
                server_pass.append(c)
            if done % 200 == 0:
                print(f"  server-test {done}/{len(unique)}  canlı: {len(server_pass)}", flush=True)
    print(f"[BİLGİ] Server testi bitti: {len(server_pass)}/{len(unique)} canlı", flush=True)

    # ---------- TUNNEL TEST ----------
    tunnel_pass = []
    if os.path.exists(XRAY_PATH) and server_pass:
        print(f"[BİLGİ] Tunnel testi başlıyor ({len(server_pass)} config)...", flush=True)
        done = 0
        with ThreadPoolExecutor(max_workers=TUNNEL_WORKERS) as ex:
            futures = {ex.submit(test_tunnel, c, XRAY_PATH): c for c in server_pass}
            for fut in as_completed(futures):
                c = futures[fut]
                done += 1
                try:
                    ok, _ = fut.result()
                except Exception:
                    ok = False
                if ok:
                    tunnel_pass.append(c)
                if done % 100 == 0:
                    print(f"  tunnel-test {done}/{len(server_pass)}  çalışan: {len(tunnel_pass)}", flush=True)
        print(f"[BİLGİ] Tunnel testi bitti: {len(tunnel_pass)}/{len(server_pass)}", flush=True)
    else:
        print("[UYARI] Xray yok veya server_pass boş, tunnel testi atlandı", flush=True)

    # ---------- SUPERS (lenient) ----------
    tunnel_set = set(tunnel_pass)
    supersub = [c for c in server_pass if c in tunnel_set] \
             + [c for c in server_pass if c not in tunnel_set]

    with open(OUTPUT_SUPERS, "w", encoding="utf-8") as f:
        f.write("\n".join(supersub) + ("\n" if supersub else ""))
    print(f"[BİLGİ] {OUTPUT_SUPERS} yazıldı -> {len(supersub)} config "
          f"({len(tunnel_pass)} tunnel-onaylı en üstte)", flush=True)


if __name__ == "__main__":
    main()
