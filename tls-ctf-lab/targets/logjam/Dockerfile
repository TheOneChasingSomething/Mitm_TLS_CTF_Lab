# C7 — Logjam (DHE export, CVE-2015-4000).
#
# Base Debian 8 « jessie » : sa pile OpenSSL (1.0.1t) embarque encore les suites
# EXPORT nécessaires au groupe Diffie-Hellman de 512 bits. Les OpenSSL récents
# (≥ 1.0.2g) les ont RETIRÉES — d'où l'épinglage d'une base héritée. jessie est
# choisi car son archive (archive.debian.org) répond encore, contrairement à
# Ubuntu 14.04 dont old-releases ne sert plus les index de trusty (404).
#
# ⚠️ Suites EXPORT vulnérables PAR CONCEPTION. Conteneur isolé uniquement.
FROM debian:8

# Debian 8 « jessie » est EOL : dépôts sur archive.debian.org, Release expirée
# (KEYEXPIRED, non bloquant). Il faut DEUX sources : `main` ET le dépôt de
# sécurité `jessie/updates` — sans ce dernier, la fermeture de dépendances des
# paquets deb8u* (apache2-bin, perl, libssl…) n'est pas résoluble.
RUN set -eux; \
    { echo 'deb http://archive.debian.org/debian jessie main'; \
      echo 'deb http://archive.debian.org/debian-security jessie/updates main'; \
    } > /etc/apt/sources.list; \
    printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; \
    apt-get update; \
    apt-get install -y --no-install-recommends --force-yes \
        apache2 openssl ca-certificates; \
    rm -rf /var/lib/apt/lists/*

RUN a2enmod ssl proxy proxy_http headers

COPY gen-certs.sh /gen-certs.sh
COPY logjam-ssl.conf /etc/apache2/sites-available/logjam.conf
RUN sh /gen-certs.sh bank.tp.lan /etc/apache2/certs \
 && a2dissite 000-default 2>/dev/null || true \
 && ln -sf /etc/apache2/sites-available/logjam.conf /etc/apache2/sites-enabled/logjam.conf

# Le flag du cookie est injecté au démarrage via l'environnement (FLAG_C7).
ENV FLAG_C7="FLAG{export_dh_512_is_precomputable}"
EXPOSE 8448
# APACHE_* : variables attendues par les scripts apache2 d'Ubuntu.
ENV APACHE_RUN_USER=www-data APACHE_RUN_GROUP=www-data \
    APACHE_PID_FILE=/var/run/apache2.pid APACHE_RUN_DIR=/var/run/apache2 \
    APACHE_LOCK_DIR=/var/lock/apache2 APACHE_LOG_DIR=/var/log/apache2
RUN mkdir -p /var/run/apache2 /var/lock/apache2
CMD ["apache2", "-DFOREGROUND"]
