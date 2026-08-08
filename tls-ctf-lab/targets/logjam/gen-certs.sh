#!/usr/bin/env sh
# C7 logjam. Certificat auto-signe + parametres DH (le groupe faible est la faille)
#
# SAN portable : l'option -addext de `openssl req` n'existe qu'a partir d'OpenSSL
# 1.1.1, absente des piles heritees (ubuntu:14.04 = 1.0.1f ; httpd:2.4.29). On
# passe donc par un fichier de config (x509_extensions), valable de 1.0.2 a 3.x.
# Le fichier temporaire est cree hors du dossier des certificats et nettoye meme
# en cas d'echec (trap EXIT).
set -eu
CN="${1:-bank.tp.lan}"
OUT="${2:-/etc/apache2/certs}"
mkdir -p "$OUT"

CNF="$(mktemp)"
trap 'rm -f "$CNF"' EXIT
cat > "$CNF" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no

[dn]
C = FR
O = TP-TLS
CN = $CN

[v3_req]
subjectAltName = DNS:$CN
EOF

openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
  -keyout "$OUT/server.key" -out "$OUT/server.crt" \
  -days 365 -config "$CNF"
# Parametres DH de 512 bits (coeur de Logjam). NB option 1 : a remplacer par
# le groupe friable dhparams.pem pour un log discret cassable en seance.
openssl dhparam -out "$OUT/dh512.pem" 512
test -s "$OUT/server.crt"   # garde-fou : echec franc si le certificat est vide
echo "[logjam] certificat + dhparam generes dans $OUT"
