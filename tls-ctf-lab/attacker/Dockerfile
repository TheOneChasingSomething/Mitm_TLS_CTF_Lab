# Point d'appui « attaquant » du mode centralisé (salle de TP anti-triche).
#
# L'étudiant est déposé dans ce conteneur par SSH (ForceCommand) : il y dispose
# des outils d'attaque, sur le MÊME réseau isolé que SA victime et SES cibles,
# mais SANS accès à l'hôte, au socket Docker, ni aux instances des autres.
# Il ne peut donc pas extraire les flags hors-bande : il doit mener les attaques.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-scapy unzip \
      tcpdump tshark nmap dsniff net-tools iptables \
      openssl curl ca-certificates iproute2 iputils-ping procps xclip xxd\
      less nano vim-tiny neovim proxychains \
      libusb-1.0-0 wget \
 && curl -s https://api.github.com/repos/bettercap/bettercap/releases/latest \
      | grep "browser_download_url.*linux_amd64.zip" \
      | cut -d : -f 2,3 \
      | tr -d \" \
      | wget -i - -O /tmp/bettercap.zip \
 && unzip /tmp/bettercap.zip -d /usr/local/bin/ \
 && chmod +x /usr/local/bin/bettercap \
 && rm -rf /tmp/bettercap.zip /var/lib/apt/lists/*

# Création de l'utilisateur ansible (UID 1000) et des répertoires associés
RUN useradd -m -u 1000 -s /bin/bash ansible \
 && mkdir -p /captures /work \
 && chown -R ansible:ansible /captures /work

USER root

# Corrigez la fin du Dockerfile comme suit :

RUN echo "Bienvenue sur votre poste d'attaque (instance isolée)." > /etc/motd && \
    echo "Cibles et victime sont sur CE réseau : résolvez-les par nom (ex. c3-mitm-http, victim-client)." >> /etc/motd && \
    echo "Portail de vérification : http://portal:5000/" >> /etc/motd

WORKDIR /captures
CMD ["sleep", "infinity"]

