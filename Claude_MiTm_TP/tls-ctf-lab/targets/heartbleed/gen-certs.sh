#!/usr/bin/env sh
# Génère les certificats auto-signés utilisés par les cibles.
# Usage : gen-certs.sh <cn> <out_dir>
set -eu
CN="${1:-bank.tp.lan}"
OUT="${2:-./certs}"
mkdir -p "$OUT"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT/server.key" -out "$OUT/server.crt" \
  -days 365 -subj "/C=FR/O=TP-TLS/CN=$CN" \
  -addext "subjectAltName=DNS:$CN"

chmod 644 "$OUT/server.key"   # permissions volontairement laxistes (cf. C2)
echo "certificat auto-signé généré pour CN=$CN dans $OUT"
