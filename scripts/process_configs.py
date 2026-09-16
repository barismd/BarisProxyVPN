#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse, parse_qs, unquote

import requests

# ---------- Ayarlar ----------
SOURCE_URLS = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt"
]

OUTPUT_SUB = "sub.txt"
OUTPUT_SUPERS = "supersub.txt"
XRAY_PATH = os.environ.get("XRAY_PATH", "xray")  # Xray-core yolu
TEST_TIMEOUT = 5  # saniye
TEST_URL = "https://www.google.com"  # test için hedef URL
# ------------------------------

def fetch_content(url):
    """URL'den içeriği indirir."""
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"[HATA] {url} indirilemedi: {e}", file=sys.stderr)
        return ""

def decode_base64_if_needed(text):
    """Metin base64 ile kodlanmışsa çözer."""
    text = text.strip()
    if not text:
        return ""
    # Base64 karakter seti kontrolü
    if re.fullmatch(r'[A-Za-z0-9+/=]+', text):
        try:
            missing = len(text) % 4
            if missing:
                text += '=' * (4 - missing)
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            # Çözülen metin de base64 olabilir (çift katmanlı)
            if re.fullmatch(r'[A-Za-z0-9+/=]+', decoded.strip()):
                try:
                    decoded2 = base64.b64decode(decoded.strip()).decode('utf-8', errors='ignore')
                    if '\n' in decoded2 or '://' in decoded2:
                        return decoded2
                except Exception:
                    pass
            return decoded
        except Exception:
            pass
    return text

def extract_configs(raw_text):
    """Ham metinden yapılandırma satırlarını ayıklar."""
    lines = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Yorum satırlarını atla
        if line.startswith('#') or line.startswith('//'):
            continue
        # Yapılandırma protokollerini kontrol et
        if re.match(r'^(vmess|vless|trojan|ss|ssr|hy2|hysteria2?)://', line, re.I):
            lines.append(line)
    return lines

def get_port_from_config(config):
    """Yapılandırmadan port numarasını çıkarır."""
    try:
        # vmess://base64(json) formatı
        if config.lower().startswith('vmess://'):
            b64 = config[8:]
            missing = len(b64) % 4
            if missing:
                b64 += '=' * (4 - missing)
            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
            data = json.loads(decoded)
            port = data.get('port')
            return int(port) if port is not None else None
        
        # trojan://, vless://, ss:// vb.
        parsed = urlparse(config)
        port = parsed.port
        if port is not None:
            return port
        # Query parametrelerinde port olabilir
        qs = parse_qs(parsed.query)
        if 'port' in qs:
            return int(qs['port'][0])
    except Exception:
        pass
    return None

def normalize_config(config):
    """Yapılandırmayı karşılaştırma için normalize eder (bağlantıya göre)."""
    # Protokol ve temel kısım dışındaki gereksiz kısımları temizle
    # Örneğin, fragment (#remark) kısmını kaldır
    if '#' in config:
        config = config.split('#')[0]
    # Sondaki boşlukları ve büyük/küçük harf farklarını gider
    return config.strip().lower()

def deduplicate_configs(configs):
    """Bağlantıya göre yinelenenleri kaldırır."""
    seen = set()
    unique = []
    for cfg in configs:
        key = normalize_config(cfg)
        if key not in seen:
            seen.add(key)
            unique.append(cfg)
    return unique

def test_config_with_xray(config, xray_path, timeout=TEST_TIMEOUT, test_url=TEST_URL):
    """
    Xray-core kullanarak yapılandırmayı test eder.
    Başarılı olursa True, aksi halde False döner.
    """
    # Yapılandırmayı Xray JSON formatına dönüştür
    # Bu kısım basitleştirilmiştir; gerçek uygulamada daha kapsamlı bir dönüştürücü gerekebilir.
    # Burada sadece vmess, vless, trojan için temel bir dönüşüm yapıyoruz.
    try:
        if config.lower().startswith('vmess://'):
            b64 = config[8:]
            missing = len(b64) % 4
            if missing:
                b64 += '=' * (4 - missing)
            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
            data = json.loads(decoded)
            outbound = {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": data.get("add"),
                        "port": int(data.get("port", 443)),
                        "users": [{
                            "id": data.get("id"),
                            "alterId": int(data.get("aid", 0)),
                            "security": data.get("scy", "auto")
                        }]
                    }]
                },
                "streamSettings": {
                    "network": data.get("net", "tcp"),
                    "security": data.get("tls", ""),
                    "tlsSettings": {
                        "serverName": data.get("host", data.get("add", ""))
                    },
                    "wsSettings": {
                        "path": data.get("path", "/")
                    }
                }
            }
        elif config.lower().startswith('vless://'):
            parsed = urlparse(config)
            params = parse_qs(parsed.query)
            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": parsed.hostname,
                        "port": parsed.port or 443,
                        "users": [{
                            "id": parsed.username,
                            "encryption": params.get("encryption", ["none"])[0],
                            "flow": params.get("flow", [""])[0]
                        }]
                    }]
                },
                "streamSettings": {
                    "network": params.get("type", ["tcp"])[0],
                    "security": params.get("security", ["none"])[0],
                    "tlsSettings": {
                        "serverName": params.get("sni", [parsed.hostname])[0]
                    },
                    "wsSettings": {
                        "path": unquote(params.get("path", ["/"])[0])
                    }
                }
            }
        elif config.lower().startswith('trojan://'):
            parsed = urlparse(config)
            params = parse_qs(parsed.query)
            outbound = {
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": parsed.hostname,
                        "port": parsed.port or 443,
                        "password": parsed.username
                    }]
                },
                "streamSettings": {
                    "network": params.get("type", ["tcp"])[0],
                    "security": params.get("security", ["tls"])[0],
                    "tlsSettings": {
                        "serverName": params.get("sni", [parsed.hostname])[0]
                    },
                    "wsSettings": {
                        "path": unquote(params.get("path", ["/"])[0])
                    }
                }
            }
        else:
            # Diğer protokoller için test yapma (şimdilik)
            return False

        # Xray yapılandırma dosyasını oluştur
        config_json = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True}
            }],
            "outbounds": [outbound]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_json, f)
            temp_config = f.name

        # Xray'i başlat
        proc = subprocess.Popen(
            [xray_path, "-config", temp_config],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1)  # Başlaması için bekle

        # Test isteği gönder
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", str(timeout),
                 "-x", "socks5://127.0.0.1:10808",
                 test_url],
                capture_output=True, text=True, timeout=timeout+2
            )
            success = result.stdout.strip() in ("200", "301", "302", "204")
        except subprocess.TimeoutExpired:
            success = False

        # Xray'i durdur
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

        os.unlink(temp_config)
        return success

    except Exception as e:
        print(f"[TEST HATASI] {config[:50]}... -> {e}", file=sys.stderr)
        return False

def main():
    all_configs = []

    # 1. Kaynaklardan verileri indir
    for url in SOURCE_URLS:
        print(f"[BİLGİ] İndiriliyor: {url}")
        raw = fetch_content(url)
        if not raw:
            continue
        decoded = decode_base64_if_needed(raw)
        configs = extract_configs(decoded)
        print(f"[BİLGİ] {len(configs)} yapılandırma bulundu.")
        all_configs.extend(configs)

    print(f"[BİLGİ] Toplam ham yapılandırma: {len(all_configs)}")

    # 2. Port filtresi (yalnızca 80 ve 443)
    filtered = []
    for cfg in all_configs:
        port = get_port_from_config(cfg)
        if port in (80, 443):
            filtered.append(cfg)
    print(f"[BİLGİ] Port filtresinden sonra: {len(filtered)}")

    # 3. Yinelenenleri kaldır (bağlantıya göre)
    unique_configs = deduplicate_configs(filtered)
    print(f"[BİLGİ] Yinelenenler kaldırıldıktan sonra: {len(unique_configs)}")

    # 4. sub.txt dosyasına yaz
    with open(OUTPUT_SUB, "w", encoding="utf-8") as f:
        for cfg in unique_configs:
            f.write(cfg + "\n")
    print(f"[BİLGİ] {OUTPUT_SUB} dosyasına yazıldı.")

    # 5. supersub.txt için test et
    print("[BİLGİ] Yapılandırmalar test ediliyor...")
    working = []
    for i, cfg in enumerate(unique_configs, 1):
        print(f"  [{i}/{len(unique_configs)}] Test ediliyor: {cfg[:60]}...")
        if test_config_with_xray(cfg, XRAY_PATH):
            working.append(cfg)
            print("    -> BAŞARILI")
        else:
            print("    -> BAŞARISIZ")

    with open(OUTPUT_SUPERS, "w", encoding="utf-8") as f:
        for cfg in working:
            f.write(cfg + "\n")
    print(f"[BİLGİ] {OUTPUT_SUPERS} dosyasına {len(working)} çalışan yapılandırma yazıldı.")

if __name__ == "__main__":
    main()
