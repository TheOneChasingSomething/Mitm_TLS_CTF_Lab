#!/usr/bin/env sh
# Certificat auto-signé pour la cible BEAST (identité non pertinente ici :
# la faille est le protocole TLS 1.0/CBC, pas l'identité).
set -eu
CN="${1:-bank.tp.lan}"
OUT="${2:-./certs}"
mkdir -p "$OUT"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT/server.key" -out "$OUT/server.crt" \
  -days 365 -subj "/C=FR/O=TP-TLS/CN=$CN" -addext "subjectAltName=DNS:$CN"
chmod 644 "$OUT/server.key"
echo "[beast] certificat auto-signé généré pour CN=$CN"
