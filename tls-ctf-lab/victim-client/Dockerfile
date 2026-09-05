# --- Étage 1 : compile OpenSSL 1.0.1f (parle encore SSLv3 + TLS 1.0), que
#     l'OpenSSL 3.x de python:3.12 ne peut plus négocier. Sert au rejeu HÉRITÉ
#     de C9 (POODLE, -ssl3) et C10 (BEAST, -tls1). Build en SÉRIE (race libcrypto).
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

# Tentative de téléchargement avec repli sur GitHub en cas d'échec
RUN (wget -q https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz || \
     wget -q https://artfiles.org/openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz || \
     wget --no-check-certificate -q https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_0_1f.tar.gz -O openssl-1.0.1f.tar.gz) \
 && tar xzf openssl-1.0.1f.tar.gz \
 && if [ -d openssl-1.0.1f ]; then cd openssl-1.0.1f; else cd openssl-OpenSSL_1_0_1f; fi \
 && ./config --prefix=/opt/openssl-vuln shared \
 && make \
 && make install_sw
 

# --- Étage 2 : image finale de la victime ---
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

# Installation des paquets système et outils réseau dans l'image finale
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 \
      net-tools \
      iputils-ping \
      tcpdump \
      curl \
      ca-certificates \
      procps \
      less \
      nano \
 && rm -rf /var/lib/apt/lists/*

# Binaire OpenSSL 1.0.1f pour le rejeu SSLv3/TLS1.0 (les libs jessie tournent sur
# bookworm : glibc rétro-compatible). Utilisé par _legacy_replay() dans client.py.
COPY --from=ossl101f /opt/openssl-vuln /opt/openssl-vuln

WORKDIR /srv
COPY client.py .

RUN useradd -r -u 10002 victim && mkdir -p /data && chown victim /data
USER victim

CMD ["python", "client.py"]