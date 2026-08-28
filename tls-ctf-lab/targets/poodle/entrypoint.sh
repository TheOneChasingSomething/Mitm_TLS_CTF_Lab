#!/bin/sh
# C9 POODLE — sert le flag sur une VRAIE session SSLv3/CBC (OpenSSL 1.0.1f).
# Le flag voyage dans un Set-Cookie (et le corps) au chemin interrogé par la
# victime (/c/9/flag-feed) : l'oracle de padding POODLE le reconstitue octet par
# octet depuis une position d'homme-du-milieu.
set -eu
: "${FLAG_C9:=FLAG{sslv3_cbc_padding_is_an_oracle}}"
export LD_LIBRARY_PATH=/opt/openssl-vuln/lib
SSL=/opt/openssl-vuln/bin/openssl

body="SECURE-FEED poodle-sslv3
flag=${FLAG_C9}
"
len=$(printf '%s' "$body" | wc -c)
mkdir -p /srv/www/c/9
# -HTTP : le fichier servi doit contenir la RÉPONSE HTTP complète.
{
  printf 'HTTP/1.0 200 OK\r\n'
  printf 'Content-Type: text/plain\r\n'
  printf 'Set-Cookie: SESSIONFLAG=%s; Path=/\r\n' "$FLAG_C9"
  printf 'Content-Length: %s\r\n' "$len"
  printf 'Connection: close\r\n'
  printf '\r\n'
  printf '%s' "$body"
} > /srv/www/c/9/flag-feed

echo "[poodle] OpenSSL $($SSL version) — service SSLv3/CBC sur :8444"
cd /srv/www
exec "$SSL" s_server \
  -cert /srv/certs/server.crt -key /srv/certs/server.key \
  -accept 8444 -HTTP -ssl3 \
  -cipher 'AES128-SHA:AES256-SHA:DES-CBC3-SHA'
