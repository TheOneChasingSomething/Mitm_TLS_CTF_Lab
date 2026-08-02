"""
beacon.py — Cible du challenge « Prise en main de Scapy » (C2).

Deux comportements, pour couvrir les deux moitiés de Scapy :

  1. BALISE (apprendre à RENIFLER) : émet périodiquement un paquet UDP en
     broadcast sur le port 8452, contenant une consigne en clair. L'étudiant la
     capture avec sniff(filter="udp port 8452").

  2. RÉPONDEUR (apprendre à FORGER / ENVOYER) : écoute l'UDP/8452 et, lorsqu'il
     reçoit le datagramme « magique » (payload commençant par MAGIC), répond à
     l'émetteur par un datagramme contenant le flag. L'étudiant doit donc forger
     et émettre le bon paquet, puis renifler la réponse.

Le flag est lu depuis l'environnement (FLAG_C2) → rotation par promotion.

⚠️ Usage strictement laboratoire (réseau isolé).
"""

import os
import threading
import time

from scapy.all import IP, UDP, Ether, Raw, send, sendp, sniff  # type: ignore

FLAG = os.environ.get("FLAG_C2", "FLAG{sniff_dissect_craft_send}").encode()
PORT = int(os.environ.get("BEACON_PORT", "8452"))
MAGIC = b"GIVE-FLAG"
BEACON_MSG = (
    b"TP-TLS/scapy-warmup: renifle-moi puis renvoie un UDP/%d dont le "
    b"payload commence par '%s' pour recevoir le flag." % (PORT, MAGIC)
)


def _beacon_loop() -> None:
    """Diffuse la consigne en broadcast L2 toutes les 5 secondes."""
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IP(dst="255.255.255.255")
        / UDP(sport=PORT, dport=PORT)
        / Raw(load=BEACON_MSG)
    )
    while True:
        try:
            sendp(pkt, verbose=False)
        except Exception as exc:  # noqa: BLE001 — lab
            print(f"[beacon] émission impossible: {exc}", flush=True)
        time.sleep(5)


def _on_magic(pkt) -> None:
    """Répond au demandeur légitime avec le flag."""
    if not (pkt.haslayer(UDP) and pkt.haslayer(Raw)):
        return
    if pkt[UDP].dport != PORT:
        return
    if not bytes(pkt[Raw].load).startswith(MAGIC):
        return
    src_ip = pkt[IP].src
    src_port = pkt[UDP].sport
    reply = IP(dst=src_ip) / UDP(sport=PORT, dport=src_port) / Raw(
        load=b"flag=" + FLAG
    )
    send(reply, verbose=False)
    print(f"[beacon] paquet magique reçu de {src_ip}:{src_port} → flag renvoyé.",
          flush=True)


def main() -> None:
    print(f"[beacon] démarrage — balise + répondeur UDP/{PORT}", flush=True)
    threading.Thread(target=_beacon_loop, daemon=True).start()
    # Boucle de réponse : ne filtre QUE l'UDP/8452 pour rester léger.
    sniff(filter=f"udp port {PORT}", prn=_on_magic, store=False)


if __name__ == "__main__":
    main()
