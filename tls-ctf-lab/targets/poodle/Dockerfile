# C9 — POODLE. Base Apache HÉRITÉE : les images httpd récentes sont liées à un
# OpenSSL qui a retiré SSL 3.0, rendant POODLE non reproductible. On épingle donc
# une image ancienne dont la pile OpenSSL parle encore SSLv3.
#
# ⚠️ Image volontairement obsolète et vulnérable. Usage strictement laboratoire,
#    jamais exposée à un réseau routable.
FROM httpd:2.4.29

# Génération du certificat (openssl de l'image héritée).
# Debian 8 « jessie » est EOL : ses dépôts ont migré vers archive.debian.org
# (les miroirs courants renvoient 404). On repointe APT vers l'archive et on
# désactive le contrôle « Valid-Until » (fichiers Release expirés) AVANT toute
# installation. Le codename est détecté depuis la sources.list de l'image.
RUN set -eux; \
    codename="$(sed -n 's|^deb http[s]*://[^ ]* \([a-z][a-z]*\) main.*|\1|p' /etc/apt/sources.list | head -n1)"; \
    [ -n "$codename" ] || codename=jessie; \
    printf 'deb http://archive.debian.org/debian %s main\n' "$codename" > /etc/apt/sources.list; \
    rm -f /etc/apt/sources.list.d/*.list 2>/dev/null || true; \
    printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; \
    apt-get update && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
COPY gen-certs.sh /gen-certs.sh
RUN sh /gen-certs.sh bank.tp.lan /usr/local/apache2/certs

COPY httpd-ssl.conf /usr/local/apache2/conf/extra/httpd-ssl.conf
RUN echo "Include conf/extra/httpd-ssl.conf" >> /usr/local/apache2/conf/httpd.conf

# Le flag du cookie est injecté au démarrage via l'environnement (FLAG_C9).
ENV FLAG_C9="FLAG{sslv3_cbc_padding_is_an_oracle}"
EXPOSE 8444
