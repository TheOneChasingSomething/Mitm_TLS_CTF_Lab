# Point d'appui « attaquant » du mode centralisé (salle de TP anti-triche).
#
# L'étudiant est déposé dans ce conteneur par SSH (ForceCommand) : il y dispose
# des outils d'attaque, sur le MÊME réseau isolé que SA victime et SES cibles,
# mais SANS accès à l'hôte, au socket Docker, ni aux instances des autres.
# Il ne peut donc pas extraire les flags hors-bande : il doit mener les attaques.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-scapy \
      tcpdump tshark nmap dsniff \
      openssl curl ca-certificates iproute2 iputils-ping \
      less nano vim-tiny \
 && rm -rf /var/lib/apt/lists/*

# Un utilisateur non-privilégié à l'intérieur du conteneur (le NET_RAW nécessaire
# à Scapy/arpspoof est accordé au conteneur, pas à l'étudiant sur l'hôte).
WORKDIR /work
RUN printf '%s\n' \
  "Bienvenue sur votre poste d'attaque (instance isolée)." \
  "Cibles et victime sont sur CE réseau : résolvez-les par nom (ex. c3-mitm-http, victim-client)." \
  "Portail de vérification : http://portal:5000/" \
  > /etc/motd
CMD ["sleep", "infinity"]
