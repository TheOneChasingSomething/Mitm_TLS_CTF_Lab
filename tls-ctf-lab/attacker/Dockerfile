# --- Étage 1 : OpenSSL 1.0.1f (parle encore SSLv3 + TLS 1.0), que l'OpenSSL 3.x
#     de debian:12 ne peut plus négocier. Donne à l'étudiant un client SSLv3 pour
#     C9 (POODLE) / C10 (BEAST) : détection, lecture directe, et PoC d'oracle.
FROM debian:8 AS ossl101f
RUN set -eux; \
    { echo 'deb http://archive.debian.org/debian jessie main'; \
      echo 'deb http://archive.debian.org/debian-security jessie/updates main'; \
    } > /etc/apt/sources.list; \
    printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; \
    apt-get update; \
    apt-get install -y --no-install-recommends --force-yes \
        build-essential wget ca-certificates; \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build

# Téléchargement robuste d'OpenSSL 1.0.1f avec replis (fallbacks).
RUN (wget -q https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz || \
     wget -q https://artfiles.org/openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz || \
     wget --no-check-certificate -q https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_0_1f.tar.gz -O openssl-1.0.1f.tar.gz) \
 && tar xzf openssl-1.0.1f.tar.gz \
 && if [ -d openssl-1.0.1f ]; then cd openssl-1.0.1f; else cd openssl-OpenSSL_1_0_1f; fi \
 && ./config --prefix=/opt/openssl-vuln shared \
 && make \
 && make install_sw

# --- Étage 2 : poste d'attaque (mode centralisé anti-triche) ---
# L'étudiant est déposé dans ce conteneur par SSH (ForceCommand) : il y dispose
# des outils d'attaque, sur le MÊME réseau isolé que SA victime et SES cibles,
# mais SANS accès à l'hôte, au socket Docker, ni aux instances des autres.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-scapy unzip \
      tcpdump tshark nmap dsniff net-tools iptables \
      openssl curl ca-certificates iproute2 iputils-ping procps xclip xxd\
      less nano vim-tiny neovim proxychains \
      libusb-1.0-0 wget \
 && curl -s https://api.github.com/repos/bettercap/bettercap/releases/latest \
      | grep "browser_download_url.*linux_amd64.zip" \
      | cut -d : -f 2,3 \
      | tr -d \" \
      | wget -i - -O /tmp/bettercap.zip \
 && unzip /tmp/bettercap.zip -d /usr/local/bin/ \
 && chmod +x /usr/local/bin/bettercap \
 && rm -rf /tmp/bettercap.zip /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages cryptography ipython

# OpenSSL 1.0.1f hérité (SSLv3/TLS1.0) + wrapper `openssl-legacy` dans le PATH.
# Ex. : openssl-legacy s_client -connect c9-poodle:8444 -ssl3 -cipher AES128-SHA
COPY --from=ossl101f /opt/openssl-vuln /opt/openssl-vuln
RUN printf '#!/bin/sh\nexec env LD_LIBRARY_PATH=/opt/openssl-vuln/lib /opt/openssl-vuln/bin/openssl "$@"\n' \
      > /usr/local/bin/openssl-legacy && chmod +x /usr/local/bin/openssl-legacy

RUN useradd -m -u 1000 -s /bin/bash ansible \
 && mkdir -p /captures /work \
 && chown -R ansible:ansible /captures /work

RUN echo "Bienvenue sur votre poste d'attaque (instance isolee)." > /etc/motd && \
    echo "Cibles et victime sont sur CE reseau : resolvez-les par nom (ex. c3-mitm-http, victim-client)." >> /etc/motd && \
    echo "Client SSLv3/TLS1.0 herite : openssl-legacy (ex. openssl-legacy s_client -connect c9-poodle:8444 -ssl3)." >> /etc/motd && \
    echo "Portail de verification : http://portal:5000/" >> /etc/motd

WORKDIR /captures
CMD ["sleep", "infinity"]