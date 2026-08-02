#!/bin/sh
# Lance un service TLS adossé à l'OpenSSL 1.0.1f vulnérable.
# Le flag est déposé dans la page servie afin de résider dans le tas → il sera
# ramené par le dump Heartbleed de l'étudiant (RFC 6520, lecture hors-limites).
set -eu

export LD_LIBRARY_PATH=/opt/openssl-vuln/lib
SSL=/opt/openssl-vuln/bin/openssl

mkdir -p /srv/www
cat > /srv/www/index.html <<EOF
<html><body>
<h1>Espace client — battement de coeur actif</h1>
<!-- secret résident en mémoire : ${FLAG_C11} -->
</body></html>
EOF

echo "[heartbleed] OpenSSL $(${SSL} version) — service TLS sur :8445"
# -HTTP sert /srv/www ; chaque requête recharge la page (flag) en mémoire.
exec "$SSL" s_server \
  -cert /srv/certs/server.crt -key /srv/certs/server.key \
  -accept 8445 -HTTP
