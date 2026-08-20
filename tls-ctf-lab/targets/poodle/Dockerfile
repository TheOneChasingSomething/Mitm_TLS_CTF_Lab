# C9 — POODLE. Base Apache HÉRITÉE : les images httpd récentes sont liées à un
# OpenSSL qui a retiré SSL 3.0, rendant POODLE non reproductible. On épingle donc
# une image ancienne dont la pile OpenSSL parle encore SSLv3.
#
# ⚠️ Image volontairement obsolète et vulnérable. Usage strictement laboratoire,
#    jamais exposée à un réseau routable.
FROM httpd:2.4.29

# Génération du certificat (openssl de l'image héritée, base Debian jessie).
# Dépôts migrés vers archive.debian.org. Deux points spécifiques à l'apt de
# jessie (ancien) : (1) Release expirée -> Check-Valid-Until false ;
# (2) paquets « non authentifiés » (clé d'archive expirée) -> `--force-yes`
# (et NON `--allow-unauthenticated`, insuffisant sur cet apt).
RUN set -eux; \
    codename="$(sed -n 's|^deb http[s]*://[^ ]* \([a-z][a-z]*\) main.*|\1|p' /etc/apt/sources.list | head -n1)"; \
    [ -n "$codename" ] || codename=jessie; \
    { echo "deb http://archive.debian.org/debian ${codename} main"; \
      echo "deb http://archive.debian.org/debian-security ${codename}/updates main"; \
    } > /etc/apt/sources.list; \
    rm -f /etc/apt/sources.list.d/*.list 2>/dev/null || true; \
    printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; \
    apt-get update; \
    apt-get install -y --no-install-recommends --force-yes openssl; \
    rm -rf /var/lib/apt/lists/*
COPY gen-certs.sh /gen-certs.sh
RUN sh /gen-certs.sh bank.tp.lan /usr/local/apache2/certs

COPY httpd-ssl.conf /usr/local/apache2/conf/extra/httpd-ssl.conf
RUN echo "Include conf/extra/httpd-ssl.conf" >> /usr/local/apache2/conf/httpd.conf

# Le flag du cookie est injecté au démarrage via l'environnement (FLAG_C9).
ENV FLAG_C9="FLAG{sslv3_cbc_padding_is_an_oracle}"
EXPOSE 8444
