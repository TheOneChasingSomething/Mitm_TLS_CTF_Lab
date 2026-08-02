FROM nginx:1.27-alpine
RUN apk add --no-cache openssl
COPY nginx.conf /etc/nginx/nginx.conf
COPY gen-certs.sh /gen-certs.sh
# Certificat auto-signé généré à la construction (CN = domaine du lab).
RUN sh /gen-certs.sh bank.tp.lan /etc/nginx/certs
EXPOSE 8441
