#!/usr/bin/env sh
# C1 openssl-warmup. Le flag est embarque dans l'OU du certificat (openssl x509 -text)
#
# SAN portable : l'option -addext de `openssl req` n'existe qu'a partir d'OpenSSL
# 1.1.1, absente des piles heritees (ubuntu:14.04 = 1.0.1f ; httpd:2.4.29). On
# passe donc par un fichier de config (x509_extensions), valable de 1.0.2 a 3.x.
# Le fichier temporaire est cree hors du dossier des certificats et nettoye meme
# en cas d'echec (trap EXIT).
set -eu
CN="${1:-bank.tp.lan}"
OUT="${2:-./certs}"
# Affectation robuste du flag : NE PAS utiliser ${3:-FLAG{...}} car le premier
# '}' du flag fermerait prematurement l'expansion (=> '}' en trop dans l'OU).
if [ "$#" -ge 3 ] && [ -n "$3" ]; then
  FLAG="$3"
else
  FLAG="FLAG{asn1_walk_then_verify_the_signature}"
fi
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
OU = $FLAG
CN = $CN

[v3_req]
subjectAltName = DNS:$CN
EOF

openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
  -keyout "$OUT/server.key" -out "$OUT/server.crt" \
  -days 365 -config "$CNF"
test -s "$OUT/server.crt"   # garde-fou : echec franc si le certificat est vide
echo "[openssl-warmup] certificat auto-signe genere (flag en OU) pour CN=$CN"
