# C6 — Absence de forward secrecy (échange RSA). Front-end nginx n'offrant que
# des suites à échange de clés RSA (kRSA), avec la clé privée du serveur exposée.
FROM nginx:1.27-alpine
RUN apk add --no-cache openssl
COPY nginx.conf /etc/nginx/nginx.conf
COPY gen-certs.sh /gen-certs.sh
RUN sh /gen-certs.sh bank.tp.lan /etc/nginx/certs
EXPOSE 8447
