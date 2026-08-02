# C11 — Heartbleed (CVE-2014-0160). On COMPILE OpenSSL 1.0.1f (extension Heartbeat
# vulnérable, RFC 6520) puis on lance un service TLS avec `openssl s_server`.
# Le flag est placé dans la page servie : il réside donc dans le tas du processus
# et devient exfiltrable par la lecture hors-limites Heartbleed (jusqu'à 64 Ko).
#
# ⚠️ OpenSSL 1.0.1f est vulnérable PAR CONCEPTION ici. Conteneur à n'exécuter
#    QUE dans le réseau de laboratoire isolé, jamais routable.
FROM ubuntu:14.04

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential wget ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
# Archive officielle des anciennes versions OpenSSL.
RUN wget -q https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz \
 && tar xzf openssl-1.0.1f.tar.gz \
 && cd openssl-1.0.1f \
 && ./config --prefix=/opt/openssl-vuln shared \
 && make -j"$(nproc)" && make install_sw

WORKDIR /srv
COPY gen-certs.sh /gen-certs.sh
COPY entrypoint.sh /entrypoint.sh
# Le flag est écrit dans la page servie → présent en mémoire du processus.
ENV FLAG_C11="FLAG{heartbeat_payload_length_unchecked}"
RUN sh /gen-certs.sh bank.tp.lan /srv/certs && chmod +x /entrypoint.sh

EXPOSE 8445
ENTRYPOINT ["/entrypoint.sh"]
