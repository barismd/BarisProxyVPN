#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote, quote

import requests

SOURCE_URLS = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
]

OUTPUT_SUB = "sub.txt"
OUTPUT_SUPERS = "supersub.txt"
XRAY_PATH = os.environ.get("XRAY_PATH", "./xray-core/xray")
SOCKS_PORT = 10808
TEST_URL = "http://www.gstatic.com/generate_204"
TEST_TIMEOUT = 6
MAX_WORKERS = 20

CONFIG_RE = re.compile(
    r'^(vmess|vless|trojan|ss|ssr|hy2|hysteria2|hysteria)://',
    re.IGNORECASE,
)


# ---------------- fetch / decode ----------------

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
    # base64 gövde kontrolü
    compact = re.sub(r'\s+', '', text)
    if re.fullmatch(r'[A-Za-z0-9+/=_-]+', compact) and len(compact) > 40:
        d1 = try_b64(compact)
        if d1 and ('://' in d1 or '\n' in d1):
            # iç içe base64 olabilir
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


# ---------------- port ----------------

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


# ---------------- dedup ----------------

def normalize(cfg):
    c = cfg.split("#", 1)[0].strip().lower()
    return c


def dedup(configs):
    seen = set()
    out = []
    for c in configs:
        k = normalize(c)
        if k and k not in seen:
            seen.add(k)
            out.append(c)
    return out


# ---------------- xray outbound builders ----------------

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
    elif net == "h2" or net == "http":
        stream["network"] = "h2"
        stream["httpSettings"] = {
            "path": path,
            "host": [host] if host else [],
        }
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
        rs = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
        }
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
    elif net == "h2" or net == "http":
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
    elif net == "h2" or net == "http":
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
    # ss://base64(method:pass)@host:port  veya  ss://method:pass@host:port
    body = uri[5:]
    if "#" in body:
        body, _ = body.split("#", 1)
    if "?" in body:
        body, _ = body.split("?", 1)
    if "@" not in body:
        # tüm gövde base64
        pad = (-len(body)) % 4
        decoded = base64.b64decode(body + "=" * pad).decode("utf-8", errors="ignore")
        body = decoded
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        if ":" not in userinfo:
            pad = (-len(userinfo)) % 4
            userinfo = base64.b64decode(userinfo + "=" * pad).decode("utf-8", errors="ignore")
        method, password = userinfo.split(":", 1)
        host, port = hostport.rsplit(":", 1)
    else:
        return None

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
    return None  # ssr / hy2 / hysteria şimdilik desteklenmiyor


# ---------------- test ----------------

def wait_port(host, port, proc, timeout=5.0):
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


def test_config(uri, xray_path):
    outbound = None
    try:
        outbound = build_outbound(uri)
    except Exception as e:
        return False, f"build error: {e}"
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
            stderr=subprocess.PIPE,
        )
        if not wait_port("127.0.0.1", SOCKS_PORT, proc, timeout=4.0):
            err = b""
            try:
                if proc.stderr:
                    err = proc.stderr.read(400)
            except Exception:
                pass
            return False, f"xray not up: {err[:200]!r}"

        # curl ile test
        try:
            res = subprocess.run(
                [
                    "curl", "-s", "-o", "/dev/null",
                    "-w", "%{http_code}",
                    "--max-time", str(TEST_TIMEOUT),
                    "--socks5-hostname", f"127.0.0.1:{SOCKS_PORT}",
                    TEST_URL,
                ],
                capture_output=True, text=True, timeout=TEST_TIMEOUT + 3,
            )
            code = res.stdout.strip()
            ok = code in ("200", "204", "301", "302")
            return ok, code
        except subprocess.TimeoutExpired:
            return False, "curl timeout"
    except Exception as e:
        return False, f"test error: {e}"
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


# ---------------- main ----------------

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

    # port filtresi
    filtered = []
    for c in all_cfgs:
        p = get_port(c)
        if p in (80, 443):
            filtered.append(c)
    print(f"[BİLGİ] Port filtresi sonrası: {len(filtered)}", flush=True)

    # dedup
    unique = dedup(filtered)
    print(f"[BİLGİ] Dedup sonrası: {len(unique)}", flush=True)

    # sub.txt
    with open(OUTPUT_SUB, "w", encoding="utf-8") as f:
        f.write("\n".join(unique) + ("\n" if unique else ""))
    print(f"[BİLGİ] {OUTPUT_SUB} yazıldı", flush=True)

    # test
    if not os.path.exists(XRAY_PATH):
        print(f"[HATA] Xray bulunamadı: {XRAY_PATH}", file=sys.stderr, flush=True)
        with open(OUTPUT_SUPERS, "w", encoding="utf-8") as f:
            f.write("")
        sys.exit(1)

    print(f"[BİLGİ] {len(unique)} config test ediliyor...", flush=True)
    working = []
    done = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(test_config, c, XRAY_PATH): c for c in unique}
        for fut in as_completed(futures):
            c = futures[fut]
            done += 1
            try:
                ok, info = fut.result()
            except Exception as e:
                ok, info = False, f"exc: {e}"
            if ok:
                working.append(c)
                print(f"[{done}/{len(unique)}] OK  {info}  {c[:70]}", flush=True)
            else:
                if done % 50 == 0 or done == len(unique):
                    print(f"[{done}/{len(unique)}] ... çalışan: {len(working)}", flush=True)

    # dedup working
    working = dedup(working)

    with open(OUTPUT_SUPERS, "w", encoding="utf-8") as f:
        f.write("\n".join(working) + ("\n" if working else ""))
    print(f"[BİLGİ] {OUTPUT_SUPERS} yazıldı: {len(working)} çalışan config", flush=True)


if __name__ == "__main__":
    main()
