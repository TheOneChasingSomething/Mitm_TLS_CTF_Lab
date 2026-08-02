# C10 — BEAST (TLS 1.0/CBC, CVE-2011-3389).
#
# ⚠️ TLS 1.0 est désormais retiré ou désactivé dans de nombreuses piles OpenSSL
#    récentes. On réactive TLS 1.0 + suites CBC via openssl-lab.cnf (SECLEVEL=0).
#    Si l'image de base a été compilée SANS TLS 1.0, remplacez la base par une
#    image héritée (ex. httpd:2.4.29, cf. cible POODLE) — voir README §Caveats.
FROM nginx:1.27-alpine
RUN apk add --no-cache openssl gettext
COPY openssl-lab.cnf /etc/ssl/openssl-lab.cnf
COPY nginx.conf.template /etc/nginx/nginx.conf.template
COPY gen-certs.sh /gen-certs.sh
COPY entrypoint.sh /entrypoint.sh
RUN sh /gen-certs.sh bank.tp.lan /etc/nginx/certs && chmod +x /entrypoint.sh

# Réactive TLS 1.0/CBC au niveau OpenSSL.
ENV OPENSSL_CONF=/etc/ssl/openssl-lab.cnf
# Flag injecté dans le cookie de session au démarrage.
ENV FLAG_C10="FLAG{predictable_iv_enables_chosen_plaintext}"
EXPOSE 8446
ENTRYPOINT ["/entrypoint.sh"]
