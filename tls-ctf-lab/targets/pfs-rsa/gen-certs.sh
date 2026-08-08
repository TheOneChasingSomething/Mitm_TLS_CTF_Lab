#!/usr/bin/env sh
# C6 pfs-rsa. La cle server.key est VOLONTAIREMENT servie via nginx
#
# SAN portable : l'option -addext de `openssl req` n'existe qu'a partir d'OpenSSL
# 1.1.1, absente des piles heritees (ubuntu:14.04 = 1.0.1f ; httpd:2.4.29). On
# passe donc par un fichier de config (x509_extensions), valable de 1.0.2 a 3.x.
# Le fichier temporaire est cree hors du dossier des certificats et nettoye meme
# en cas d'echec (trap EXIT).
set -eu
CN="${1:-bank.tp.lan}"
OUT="${2:-./certs}"
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
chmod 644 "$OUT/server.key"   # LOAD-BEARING : cle servie a /.well-known/backup/ (fuite C6)
test -s "$OUT/server.crt"   # garde-fou : echec franc si le certificat est vide
echo "[pfs-rsa] certificat + cle (644, servie) generes pour CN=$CN"
