# ============================================================
# OBSIDIAN PROTOCOL — TARGET-49
# VECTOR-I: CVE-2021-41773 / CVE-2021-42013 (Apache Path Traversal/RCE)
# VECTOR-II: CVE-2021-4034 (PwnKit Local Privilege Escalation)
#
# UYARI: Bu imaj BİLEREK zafiyetli bir Apache sürümü içerir.
# Sadece izole, internete açık olmayan bir Docker range'inde çalıştırın.
# Eğitim ve portföy amaçlıdır. Üretimde KULLANMAYIN.
# ============================================================

FROM debian:bullseye-slim

# Build bağımlılıkları (Apache'yi kaynaktan derleyeceğiz çünkü
# Debian repo'ları zaten patch'li sürüm dağıtıyor)
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    curl \
    libpcre3-dev \
    libssl-dev \
    zlib1g-dev \
    libapr1-dev \
    libaprutil1-dev \
    sudo \
    cgi-bin \
    && rm -rf /var/lib/apt/lists/*

# === Zafiyetli sürüm: tam olarak 2.4.49 ===
WORKDIR /usr/src
RUN wget https://archive.apache.org/dist/httpd/httpd-2.4.49.tar.gz \
    && tar -xzf httpd-2.4.49.tar.gz

WORKDIR /usr/src/httpd-2.4.49
RUN ./configure \
    --prefix=/usr/local/apache2 \
    --enable-cgi \
    --enable-cgid \
    --with-mpm=prefork \
    && make -j$(nproc) \
    && make install

# CGI script çalıştırılabilir hale getir (VECTOR-I'in RCE
# tarafı mod_cgi'nin aktif olmasını gerektirir)
RUN mkdir -p /usr/local/apache2/cgi-bin

# --- Düşük yetkili sistem kullanıcısı (priv-esc senaryosu için) ---
RUN useradd -m -s /bin/bash labuser && \
    echo "labuser:LabPass123!" | chpasswd

# === VECTOR-II (CVE-2021-4034 / PwnKit) zafiyeti kuruluyor ===
COPY setup-pwnkit.sh /tmp/setup-pwnkit.sh
RUN chmod +x /tmp/setup-pwnkit.sh && /tmp/setup-pwnkit.sh

# Apache'yi bu kullanıcı altında çalıştır (gerçekçi senaryo:
# web server genelde root değil, sınırlı bir kullanıcı olarak çalışır)
RUN sed -i 's/^User .*/User labuser/' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's/^Group .*/Group labuser/' /usr/local/apache2/conf/httpd.conf

# mod_cgi'yi aktif et + CGI dizinine izin ver (VECTOR-I'in RCE koşulu)
COPY httpd-vuln.conf /usr/local/apache2/conf/extra/httpd-vuln.conf
RUN echo "Include conf/extra/httpd-vuln.conf" >> /usr/local/apache2/conf/httpd.conf

# Sahte "iç ağ" dosyası — path traversal ile okunabilir olacak
# (gerçek bir pentest'te burada /etc/passwd, config dosyaları,
# SSH key'leri vs. olur — biz lab içinde sahte bir secret koyuyoruz)
RUN mkdir -p /opt/internal && \
    echo "INTERNAL_DB_PASSWORD=S3cr3t_DB_Pass_2024" > /opt/internal/secrets.env && \
    chown labuser:labuser /opt/internal/secrets.env

EXPOSE 80
WORKDIR /usr/local/apache2
CMD ["./bin/httpd", "-D", "FOREGROUND"]
