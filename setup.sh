#!/bin/bash
# ============================================================
# setup.sh — OBSIDIAN PROTOCOL Range Devreye Alma
#
# Kullanım: ./setup.sh
#
# Bu script:
#   1. Docker/docker-compose'un kurulu olduğunu doğrular
#   2. İmajları build eder
#   3. Range'i (target-49 + operator) başlatır
#   4. target-49'un HTTP'ye cevap verdiğini doğrular
#   5. operator container'ından target-49'a DNS çözümlemesinin
#      çalıştığını doğrular VE internete çıkışın kapalı olduğunu
#      kanıtlar (izolasyon garantisinin gerçekten çalıştığını
#      otomatik test eder, sadece belgelemekle kalmaz)
# ============================================================
set -e

BANNER="
  ██████╗ ██████╗ ███████╗██╗██████╗ ██╗ █████╗ ███╗   ██╗
 ██╔═══██╗██╔══██╗██╔════╝██║██╔══██╗██║██╔══██╗████╗  ██║
 ██║   ██║██████╔╝███████╗██║██║  ██║██║███████║██╔██╗ ██║
 ██║   ██║██╔══██╗╚════██║██║██║  ██║██║██╔══██║██║╚██╗██║
 ╚██████╔╝██████╔╝███████║██║██████╔╝██║██║  ██║██║ ╚████║
  ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
              P R O T O C O L
"
echo "$BANNER"
echo "=================================================="
echo "  Range devreye alınıyor — VECTOR-I / VECTOR-II"
echo "=================================================="

# --- Ön koşul kontrolü ---
if ! command -v docker &> /dev/null; then
    echo "[!] Docker bulunamadı. Lütfen Docker'ı kurun: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker compose version &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo "[!] docker-compose bulunamadı."
    exit 1
fi

COMPOSE_CMD="docker compose"
if ! docker compose version &> /dev/null; then
    COMPOSE_CMD="docker-compose"
fi

echo "[*] Docker bulundu, build başlıyor..."
$COMPOSE_CMD build

echo "[*] Range başlatılıyor (target-49 + operator)..."
$COMPOSE_CMD up -d

echo "[*] target-49 sağlık kontrolü bekleniyor (en fazla 60sn)..."
ATTEMPTS=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' obsidian-target-49 2>/dev/null)" == "healthy" ]; do
    ATTEMPTS=$((ATTEMPTS+1))
    if [ $ATTEMPTS -ge 12 ]; then
        echo "[!] target-49 60 saniye içinde healthy olmadı. Logları kontrol et:"
        echo "    docker logs obsidian-target-49"
        exit 1
    fi
    sleep 5
done
echo "[+] target-49 sağlıklı ve HTTP'ye cevap veriyor."

echo "[*] Range izolasyonu doğrulanıyor (operator -> target-49 DNS çözümlemesi)..."
docker exec obsidian-operator getent hosts target-49 || {
    echo "[!] DNS çözümlemesi başarısız - network konfigürasyonunu kontrol et."
    exit 1
}
echo "[+] İç network çözümlemesi çalışıyor."

echo "[*] İnternete çıkış engellendiğini doğrulama (bu komutun BAŞARISIZ olması beklenir)..."
if docker exec obsidian-operator timeout 3 curl -s https://1.1.1.1 &> /dev/null; then
    echo "[!] UYARI: operator container internete çıkabiliyor! docker-compose.yml'deki"
    echo "    'internal: true' ayarını kontrol et."
else
    echo "[+] İzolasyon doğrulandı: operator container internete çıkamıyor."
fi

echo ""
echo "=================================================="
echo "  Range hazır."
echo "  OPERATOR kutusuna bağlan:"
echo "    docker exec -it obsidian-operator bash"
echo "  Sonraki adım: docs/walkthrough.md (VECTOR-I başlangıcı)."
echo "=================================================="
