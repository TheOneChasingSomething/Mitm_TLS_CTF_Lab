FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

# Installation des paquets système et outils réseau dans l'image finale
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 \
      net-tools \
      iputils-ping \
      tcpdump \
      curl \
      ca-certificates \
      procps \
      less \
      nano \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY client.py .

RUN useradd -r -u 10002 victim && mkdir -p /data && chown victim /data
USER victim

CMD ["python", "client.py"]