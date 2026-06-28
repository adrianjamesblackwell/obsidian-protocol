#!/bin/bash
# ============================================================
# setup-pwnkit.sh — OBSIDIAN PROTOCOL / VECTOR-II
#
# Bu script container içine PwnKit (CVE-2021-4034) zafiyetini
# taşıyan polkit/pkexec paketini kurar.
#
# CVE-2021-4034 nedir (kısa teknik özet):
#   pkexec, argv[0]'ı (process'in çağrıldığı isim) hiçbir
#   doğrulama yapmadan kullanıyordu. argc=0 ile çağrıldığında
#   (yani process'e hiç argüman verilmediğinde) pkexec, kendi
#   argv dizisinin dışına taşarak environment'tan veri okumaya
#   başlıyordu. Bu da GCONV_PATH gibi ortam değişkenleriyle
#   keyfi shared library injection'a (root yetkisiyle) yol açtı.
#
# Etkilenen sürümler: polkit 0.105 - 0.120 arası (Debian
# bullseye'daki varsayılan sürüm dahil).
#
# Bu script bilerek PATCH EDİLMEMİŞ bir polkit sürümü bırakır.
# ============================================================
set -e

echo "[*] PwnKit (CVE-2021-4034) lab ortamı hazırlanıyor..."

apt-get update
apt-get install -y policykit-1=0.105-31  # bullseye'ın varsayılan, zafiyetli sürümü

# pkexec binary'sinin SUID bit'i taşıdığını doğrula
# (CVE-2021-4034'ün ön koşulu budur)
ls -la /usr/bin/pkexec

echo "[*] Kurulum tamamlandı. pkexec SUID bit ile kurulu."
echo "[*] Zafiyetli sürüm: $(dpkg -l | grep policykit-1)"
