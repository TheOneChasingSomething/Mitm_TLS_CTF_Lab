#!/bin/sh
# C11 Heartbleed — service TLS (OpenSSL 1.0.1f). Le flag est servi à
# /c/11/flag-feed (le chemin réellement interrogé par la victime) afin d'être
# chargé dans le TAS à chaque requête ; il devient alors exfiltrable par la
# lecture hors-limites Heartbleed (RFC 6520, jusqu'à 64 Ko).
set -eu
: "${FLAG_C11:=FLAG{heartbeat_payload_length_unchecked}}"
export LD_LIBRARY_PATH=/opt/openssl-vuln/lib
SSL=/opt/openssl-vuln/bin/openssl

body="SECURE-FEED heartbleed
flag=${FLAG_C11}
"
len=$(printf '%s' "$body" | wc -c)
mkdir -p /srv/www/c/11
{
  printf 'HTTP/1.0 200 OK\r\n'
  printf 'Content-Type: text/plain\r\n'
  printf 'Content-Length: %s\r\n' "$len"
  printf 'Connection: close\r\n'
  printf '\r\n'
  printf '%s' "$body"
} > /srv/www/c/11/flag-feed

echo "[heartbleed] OpenSSL $($SSL version) — service TLS sur :8445"
cd /srv/www
exec "$SSL" s_server \
  -cert /srv/certs/server.crt -key /srv/certs/server.key \
  -accept 8445 -HTTP
