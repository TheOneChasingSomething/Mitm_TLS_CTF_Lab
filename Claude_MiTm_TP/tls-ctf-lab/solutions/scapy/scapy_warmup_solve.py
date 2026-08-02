#!/usr/bin/env python3
"""
Correction C2 — Prise en main de Scapy (solveur de référence).

Trois gestes fondamentaux de Scapy :
  1. RENIFLER la balise UDP/8452 diffusée par la cible (sniff + filtre BPF) ;
  2. FORGER le datagramme « magique » attendu (IP/UDP/Raw) ;
  3. ÉMETTRE le paquet et renifler la réponse contenant le flag.

Usage :
  sudo python3 scapy_warmup_solve.py --target 172.28.0.22 [--iface eth0]
"""
import argparse
import re

from scapy.all import IP, UDP, Raw, sniff, sr1, conf  # type: ignore

PORT = 8452
MAGIC = b"GIVE-FLAG"
FLAG_RE = re.compile(rb"FLAG\{[^}]+\}")


def watch_beacon(iface: str | None) -> None:
    """Étape 1 : capturer une balise pour lire la consigne."""
    print(f"[*] écoute de la balise UDP/{PORT} (Ctrl-C pour passer)…")
    pkts = sniff(filter=f"udp port {PORT}", count=1, timeout=15, iface=iface)
    if pkts and pkts[0].haslayer(Raw):
        print("[+] balise reçue :", bytes(pkts[0][Raw].load).decode(errors="replace"))
    else:
        print("[!] aucune balise capturée (le répondeur fonctionne quand même).")


def solve(target: str, iface: str | None) -> str | None:
    """Étapes 2 & 3 : forger le paquet magique et lire la réponse."""
    if iface:
        conf.iface = iface
    pkt = IP(dst=target) / UDP(dport=PORT, sport=40000) / Raw(load=MAGIC)
    print(f"[*] envoi du paquet magique → {target}:{PORT} (payload={MAGIC!r})")
    reply = sr1(pkt, timeout=5, verbose=False)
    if reply is None or not reply.haslayer(Raw):
        print("[!] pas de réponse.")
        return None
    data = bytes(reply[Raw].load)
    print("[+] réponse :", data.decode(errors="replace"))
    m = FLAG_RE.search(data)
    return m.group(0).decode() if m else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="IP de la cible scapy-warmup")
    ap.add_argument("--iface", default=None, help="interface de capture/émission")
    args = ap.parse_args()

    watch_beacon(args.iface)
    flag = solve(args.target, args.iface)
    print("\n=== FLAG ===", flag if flag else "(non trouvé)")


if __name__ == "__main__":
    main()
