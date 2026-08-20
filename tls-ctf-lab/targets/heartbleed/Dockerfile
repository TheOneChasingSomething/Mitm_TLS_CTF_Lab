# C11 — Heartbleed (CVE-2014-0160). On COMPILE OpenSSL 1.0.1f (extension Heartbeat
# vulnérable, RFC 6520) puis on lance un service TLS avec `openssl s_server`.
# Le flag est placé dans la page servie : il réside donc dans le tas du processus
# et devient exfiltrable par la lecture hors-limites Heartbleed (jusqu'à 64 Ko).
#
# ⚠️ OpenSSL 1.0.1f est vulnérable PAR CONCEPTION ici. Conteneur à n'exécuter
#    QUE dans le réseau de laboratoire isolé, jamais routable.
#
# Base Debian 8 « jessie » : archive.debian.org répond encore (contrairement à
# Ubuntu 14.04/old-releases → 404) et fournit build-essential/wget pour compiler
# OpenSSL 1.0.1f depuis les sources.
FROM debian:8

# Debian 8 « jessie » EOL : DEUX sources d'archive (main + sécurité) sont
# nécessaires pour résoudre les dépendances deb8u* (gcc, g++, dpkg-dev…).
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
# Archive officielle des anciennes versions OpenSSL.
# NB : le build d'OpenSSL 1.0.1f n'est PAS parallélisable (les cibles créent
# concurremment le lien libcrypto.so -> « File exists »). On compile en SÉRIE
# (pas de -j) ; c'est un peu plus lent mais fiable, et ça ne change rien à la
# vulnérabilité Heartbeat obtenue.
RUN wget -q https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz \
 && tar xzf openssl-1.0.1f.tar.gz \
 && cd openssl-1.0.1f \
 && ./config --prefix=/opt/openssl-vuln shared \
 && make \
 && make install_sw

WORKDIR /srv
COPY gen-certs.sh /gen-certs.sh
COPY entrypoint.sh /entrypoint.sh
# Le flag est écrit dans la page servie → présent en mémoire du processus.
ENV FLAG_C11="FLAG{heartbeat_payload_length_unchecked}"
RUN sh /gen-certs.sh bank.tp.lan /srv/certs && chmod +x /entrypoint.sh

EXPOSE 8445
ENTRYPOINT ["/entrypoint.sh"]
