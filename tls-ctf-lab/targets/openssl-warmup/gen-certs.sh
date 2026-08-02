#!/usr/bin/env sh
# C1 — Prise en main d'OpenSSL.
# Génère un certificat auto-signé dont un champ (OU) EMBARQUE le flag. L'étudiant
# doit récupérer le certificat, l'inspecter, et vérifier sa signature à la main
# (parcours ASN.1, cf. README / SOLUTIONS). Le flag n'est jamais servi en HTTP.
# Usage : gen-certs.sh <cn> <out_dir> <flag>
set -eu
CN="${1:-bank.tp.lan}"
OUT="${2:-./certs}"
FLAG="${3:-FLAG{asn1_walk_then_verify_the_signature}}"
mkdir -p "$OUT"

# Le flag est placé dans l'Organizational Unit → visible via `openssl x509 -text`.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT/server.key" -out "$OUT/server.crt" \
  -days 365 -sha256 \
  -subj "/C=FR/O=TP-TLS/OU=$FLAG/CN=$CN" \
  -addext "subjectAltName=DNS:$CN"

chmod 644 "$OUT/server.key"
echo "[openssl-warmup] certificat auto-signé généré (flag embarqué en OU) pour CN=$CN"
