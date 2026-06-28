# ============================================================
# OBSIDIAN PROTOCOL — OPERATOR
# The box the attack chain (VECTOR-I / VECTOR-II) is executed from
#
# This container is used to run exploitation against the range's
# "target-49" target. It only has access to the range's own Docker
# network — it has no access to the internet or the host system
# (see the network_mode and internal: true settings in
# docker-compose.yml).
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
