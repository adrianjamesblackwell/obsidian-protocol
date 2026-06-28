# ============================================================
# OBSIDIAN PROTOCOL — OPERATOR
# Saldırı zincirinin (VECTOR-I / VECTOR-II) yürütüldüğü kutu
#
# Bu container, range'deki "target-49" hedefine karşı
# exploitation yapmak için kullanılır. Sadece range'in kendi
# Docker network'üne erişimi vardır — internete veya host
# sisteme erişimi yoktur (docker-compose.yml'deki network_mode
# ve internal: true ayarına bakın).
# ============================================================

FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    curl \
    netcat-traditional \
    python3 \
    python3-pip \
    gcc \
    git \
    nmap \
    vim \
    jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/obsidian
COPY ./tools /opt/obsidian/tools

CMD ["/bin/bash"]
