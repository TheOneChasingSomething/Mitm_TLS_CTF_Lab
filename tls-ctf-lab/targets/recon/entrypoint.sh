#!/bin/sh
# Écrit la page de reconnaissance avec le flag (env FLAG_C0) dans le TITRE HTML,
# puis lance nginx au premier plan. Le flag est ainsi lisible via le titre HTTP
# (nmap --script http-title) ou par un simple curl — après découverte du port.
set -eu
: "${FLAG_C0:=FLAG{map_the_terrain_before_the_assault}}"
mkdir -p /usr/share/nginx/html
cat > /usr/share/nginx/html/index.html <<HTML
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>${FLAG_C0}</title></head>
<body>
  <h1>Lab recon service</h1>
  <p>You found the hidden service by scanning. The flag is in this page's title.</p>
  <p>Flag: ${FLAG_C0}</p>
  <p>Next: enumerate every challenge service (IP:port) for C1..C11 with nmap.</p>
</body>
</html>
HTML
exec nginx -g 'daemon off;'
