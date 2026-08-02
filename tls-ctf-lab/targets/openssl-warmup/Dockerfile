FROM nginx:1.27-alpine
RUN apk add --no-cache openssl
COPY nginx.conf /etc/nginx/nginx.conf
COPY gen-certs.sh /gen-certs.sh
# Le flag (FLAG_C1) est injecté dans le certificat à la construction.
ARG FLAG_C1="FLAG{asn1_walk_then_verify_the_signature}"
RUN sh /gen-certs.sh bank.tp.lan /etc/nginx/certs "$FLAG_C1"
EXPOSE 8451
