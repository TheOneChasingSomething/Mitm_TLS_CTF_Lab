FROM nginx:1.27-alpine
RUN apk add --no-cache openssl
COPY nginx.conf /etc/nginx/nginx.conf
COPY gen-certs.sh /gen-certs.sh
RUN sh /gen-certs.sh bank.tp.lan /etc/nginx/certs
EXPOSE 80 8443
