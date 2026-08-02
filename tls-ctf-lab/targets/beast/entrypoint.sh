#!/bin/sh
# Injecte le flag (cookie) dans la conf puis lance nginx. envsubst ne substitue
# QUE ${FLAG_C10} afin de préserver les variables nginx ($host, etc.).
set -eu
envsubst '${FLAG_C10}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf
echo "[beast] nginx TLS 1.0/CBC sur :8446 — OpenSSL $(openssl version)"
exec nginx -g 'daemon off;'
