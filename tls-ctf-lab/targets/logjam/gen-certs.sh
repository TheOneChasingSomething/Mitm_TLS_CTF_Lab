#!/usr/bin/env sh
# Certificat auto-signé pour la cible Logjam (l'identité n'est pas la faille :
# la vulnérabilité est le groupe Diffie-Hellman export de 512 bits).
set -eu
CN="${1:-bank.tp.lan}"
OUT="${2:-/etc/apache2/certs}"
mkdir -p "$OUT"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT/server.key" -out "$OUT/server.crt" \
  -days 365 -subj "/C=FR/O=TP-TLS/CN=$CN"
# Paramètres DH EXPORT de 512 bits (le cœur de Logjam). Groupe volontairement
# faible : son logarithme discret est précalculable une fois pour toutes.
openssl dhparam -out "$OUT/dh512.pem" 512
chmod 644 "$OUT/server.key"
echo "[logjam] certificat + dhparam 512 bits générés dans $OUT"
