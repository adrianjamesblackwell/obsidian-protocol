# ============================================================
# OBSIDIAN PROTOCOL — TARGET-49
# VECTOR-I: CVE-2021-41773 / CVE-2021-42013 (Apache Path Traversal/RCE)
# VECTOR-II: CVE-2021-4034 (PwnKit Local Privilege Escalation)
#
# WARNING: This image DELIBERATELY contains a vulnerable Apache
# version. Only run it inside an isolated Docker range with no
# internet exposure. For educational and portfolio purposes only.
# Do NOT use in production.
# ============================================================

FROM debian:bullseye-slim

# Build dependencies (Apache is compiled from source because
# Debian's repositories already ship a patched version)
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

# === Vulnerable version: exactly 2.4.49 ===
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

# Make the CGI script directory executable (the RCE side of
# VECTOR-I requires mod_cgi to be active)
RUN mkdir -p /usr/local/apache2/cgi-bin

# --- Low-privilege system user (for the priv-esc scenario) ---
RUN useradd -m -s /bin/bash labuser && \
    echo "labuser:LabPass123!" | chpasswd

# === Installing the VECTOR-II (CVE-2021-4034 / PwnKit) vulnerability ===
COPY setup-pwnkit.sh /tmp/setup-pwnkit.sh
RUN chmod +x /tmp/setup-pwnkit.sh && /tmp/setup-pwnkit.sh

# Run Apache under this user (realistic scenario: a web server
# typically runs as a restricted user, not as root)
RUN sed -i 's/^User .*/User labuser/' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's/^Group .*/Group labuser/' /usr/local/apache2/conf/httpd.conf

# Enable mod_cgi + allow the CGI directory (the RCE precondition for VECTOR-I)
COPY httpd-vuln.conf /usr/local/apache2/conf/extra/httpd-vuln.conf
RUN echo "Include conf/extra/httpd-vuln.conf" >> /usr/local/apache2/conf/httpd.conf

# Fake "internal network" file — readable via path traversal
# (in a real pentest this would be /etc/passwd, config files,
# SSH keys, etc. — here we plant a fake secret inside the lab)
RUN mkdir -p /opt/internal && \
    echo "INTERNAL_DB_PASSWORD=S3cr3t_DB_Pass_2024" > /opt/internal/secrets.env && \
    chown labuser:labuser /opt/internal/secrets.env

EXPOSE 80
WORKDIR /usr/local/apache2
CMD ["./bin/httpd", "-D", "FOREGROUND"]
