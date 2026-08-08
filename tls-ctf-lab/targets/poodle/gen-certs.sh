# L'option -addext de openssl req n'existe pas dans les anciennes versions d'OpenSSL. Elle a été ajoutée dans OpenSSL 1.1.1.
# openssl req -x509 -newkey rsa:2048 -nodes \
  # -keyout "$OUT/server.key" -out "$OUT/server.crt" \
  # -days 365 -subj "/C=FR/O=TP-TLS/CN=$CN" \
  # -addext "subjectAltName=DNS:$CN"
# Modern browser need the subjectAltName extension. (Subject Alternative Name (SAN))

cat > "$OUT/openssl.cnf" <<EOF
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

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT/server.key" \
  -out "$OUT/server.crt" \
  -days 365 \
  -config "$OUT/openssl.cnf"

rm "$OUT/openssl.cnf"