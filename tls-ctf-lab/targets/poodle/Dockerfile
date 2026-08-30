# C9 — POODLE (CVE-2014-3566). SSL 3.0 exige un OpenSSL qui le parle encore : la
# libssl de Debian a SSLv3 compilé en dur DÉSACTIVÉ (mod_ssl ne peut donc PAS
# l'offrir — d'où l'échec de l'approche httpd:2.4.29). On compile OpenSSL 1.0.1f
# (comme C11) et on sert l'endpoint SSLv3/CBC via `openssl s_server`.
#
# ⚠️ Vulnérable par conception. Réseau de laboratoire isolé uniquement.
FROM debian:8

# Debian 8 « jessie » EOL : deux sources d'archive (main + sécurité) + clé
# expirée (--force-yes). openssl (système) sert à gen-certs.sh ; build-essential
# /wget à compiler 1.0.1f.
RUN set -eux; \
    { echo 'deb http://archive.debian.org/debian jessie main'; \
      echo 'deb http://archive.debian.org/debian-security jessie/updates main'; \
    } > /etc/apt/sources.list; \
    printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; \
    apt-get update; \
    apt-get install -y --no-install-recommends --force-yes \
        build-essential wget ca-certificates openssl; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
# Build NON parallélisable (race sur le lien libcrypto.so) → make en SÉRIE.
# Remplacer la ligne 24 :
RUN wget --no-check-certificate -q https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz \
    && tar xzf openssl-1.0.1f.tar.gz \
    && cd openssl-1.0.1f \
    && ./config --prefix=/opt/openssl-vuln shared \
    && make \
    && make install_sw

WORKDIR /srv
COPY gen-certs.sh /gen-certs.sh
COPY entrypoint.sh /entrypoint.sh
ENV FLAG_C9="FLAG{sslv3_cbc_padding_is_an_oracle}"
RUN sh /gen-certs.sh bank.tp.lan /srv/certs && chmod +x /entrypoint.sh
EXPOSE 8444
ENTRYPOINT ["/entrypoint.sh"]
