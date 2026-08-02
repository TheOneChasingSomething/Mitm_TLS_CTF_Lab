# C2 — Prise en main de Scapy. Cible « balise » : émet une consigne en broadcast
# et répond au paquet magique par le flag. Requiert des capacités réseau (L2).
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      tcpdump libpcap0.8 \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir scapy==2.5.0
COPY beacon.py /srv/beacon.py
ENV FLAG_C2="FLAG{sniff_dissect_craft_send}"
EXPOSE 8452/udp
# NB : nécessite NET_RAW/NET_ADMIN (cf. docker-compose) pour l'accès L2 Scapy.
CMD ["python", "/srv/beacon.py"]
