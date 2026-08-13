"""
challenges.py — Declarative definition of the "HTTPS Security" lab challenges.

Recommended solving order: C0 recon (nmap) → C1 OpenSSL / C2 Scapy warm-ups →
C3 cleartext MITM → C4 PKI identity → C5 key leak → C6 no forward secrecy →
C7 Logjam → C8 SSL stripping → C9 POODLE → C10 BEAST → C11 Heartbleed.

Each challenge declares its teaching vector, its flag-delivery mode
("encrypted_by"): tls (cleartext app-layer flag, protected ONLY by the
deliberately-breakable TLS front-end), cleartext (no TLS at all), rsa-oaep
(app-layer encrypted blob, C5), memory (flag resident in process memory,
Heartbleed C11), cert (flag embedded in the served X.509 certificate, C1),
beacon (flag emitted/answered on the network by a Scapy beacon, C2), recon
(flag carried by a service to discover by scanning, C0); the port/protocol
exposed by the TARGET; and the flag with its verification digest
(zero-disclosure verification on the portal side).

DESIGN NOTE — flags are loaded from the environment so a clean instance can be
regenerated per class / per student without rebuilding the image.
"""

import hashlib
import os

# Identity domain used by every target (resolved via the lab's /etc/hosts).
LAB_DOMAIN = os.environ.get("LAB_DOMAIN", "bank.tp.lan")


def _flag(env_key: str, default: str) -> str:
    return os.environ.get(env_key, default)


CHALLENGES = {
    "0": {
        "slug": 'recon',
        "title": 'Network reconnaissance (nmap)',
        "points": 10,
        "skill": 'Network discovery: host and port sweeping with nmap',
        "objective": "Before attacking, map the lab. With nmap, sweep the lab subnet to build the inventory of the following challenges' services (IP:port pairs for C1 to C11). A reconnaissance service hides on a non-standard port: its HTTP title contains the flag.",
        "transport": 'TCP (service discovery — no encryption)',
        "target_port": 9000,
        "encrypted_by": 'recon',
        "hint": 'nmap -sn 172.28.0.0/24 (live hosts) ; nmap -p- -sV 172.28.0.20 ; the flag is in the HTTP title (--script http-title).',
        "flag": _flag('FLAG_C0', 'FLAG{map_the_terrain_before_the_assault}'),
    },
    "1": {
        "slug": 'openssl-warmup',
        "title": 'OpenSSL warm-up',
        "points": 10,
        "skill": 'X.509 handling: generation, inspection, ASN.1 verification',
        "objective": "Retrieve the self-signed certificate served by the target, inspect it, and verify ITS OWN signature following the OpenSSL procedure (ASN.1 walk, extraction of the signature BIT STRING, RSA decryption with the public key, comparison against the digest of the body). The flag is embedded in one of the certificate's fields.",
        "transport": 'TLS 1.2 (self-signed certificate to inspect/verify)',
        "target_port": 8451,
        "encrypted_by": 'cert',
        "hint": 'openssl s_client -connect TARGET:8451 -showcerts ; openssl x509 -text ; asn1parse.',
        "flag": _flag('FLAG_C1', 'FLAG{asn1_walk_then_verify_the_signature}'),
    },
    "2": {
        "slug": 'scapy-warmup',
        "title": 'Scapy warm-up',
        "points": 10,
        "skill": 'Sniff / dissect / craft / send packets with Scapy',
        "objective": "A beacon periodically broadcasts a UDP packet on the lab network. Sniff it with Scapy to discover the instruction, then CRAFT and send the 'magic' packet the target expects: it will reply with a packet containing the flag.",
        "transport": 'UDP/8452 beacon on the lab L2 segment (broadcast)',
        "target_port": 8452,
        "encrypted_by": 'beacon',
        "hint": "sniff(filter='udp port 8452') ; then send(IP()/UDP(dport=8452)/b'GIVE-FLAG').",
        "flag": _flag('FLAG_C2', 'FLAG{sniff_dissect_craft_send}'),
    },
    "3": {
        "slug": 'mitm-http',
        "title": 'MITM against HTTP (cleartext)',
        "points": 20,
        "skill": 'Active interception: ARP spoofing + sniffing an HTTP stream',
        "objective": 'The victim client reads its statement over CLEARTEXT HTTP (no TLS). Get on-path by ARP poisoning between the victim and the target, then sniff the stream: the flag travels in cleartext in the HTTP response.',
        "transport": 'HTTP 80 cleartext (no transport encryption)',
        "target_port": 8453,
        "encrypted_by": 'cleartext',
        "hint": "arpspoof / bettercap OR Scapy (ARP is-at) ; sniff filter 'tcp port 8453'.",
        "flag": _flag('FLAG_C3', 'FLAG{cleartext_http_has_no_secrets}'),
    },
    "4": {
        "slug": 'self-signed-mitm',
        "title": 'Self-signed certificate & MITM',
        "points": 15,
        "skill": 'PKI identity validation (RFC 5280)',
        "objective": "The 'victim' client queries the secure feed while accepting any certificate. Get on-path, present your own self-signed certificate, and read the flag.",
        "transport": 'TLS 1.2 (self-signed certificate, not validated by the client)',
        "target_port": 8441,
        "encrypted_by": 'tls',
        "hint": 'bettercap / mitmproxy as a transparent proxy ; ARP spoofing of the client.',
        "flag": _flag('FLAG_C4', 'FLAG{identity_without_pki_is_no_identity}'),
    },
    "5": {
        "slug": 'private-key-leak',
        "title": 'Private-key leak',
        "points": 20,
        "skill": 'Secret management & forward secrecy',
        "objective": "The front-end mistakenly exposes the server's private key in a public directory. The flag is published as an RSA-OAEP encrypted blob. Retrieve the key, decrypt the blob.",
        "transport": 'TLS 1.2 (server private key exposed under /.well-known/)',
        "target_port": 8442,
        "encrypted_by": 'rsa-oaep',
        "hint": 'curl https://TARGET/.well-known/backup/server.key then openssl pkeyutl -decrypt.',
        "flag": _flag('FLAG_C5', 'FLAG{a_leaked_key_breaks_forward_secrecy}'),
    },
    "6": {
        "slug": 'pfs-rsa-kx',
        "title": 'No forward secrecy (RSA key exchange)',
        "points": 25,
        "skill": 'Forward secrecy: after-the-fact decryption of RSA-key-exchange traffic',
        "objective": "The server negotiates an RSA KEY EXCHANGE (no ECDHE/DHE): the pre-master secret is encrypted under the server's RSA public key, not derived from an ephemeral. Record the victim's encrypted TLS traffic, leak the (exposed) server private key, then decrypt the capture AFTER THE FACT to read the flag.",
        "transport": 'TLS 1.2 (RSA key exchange — no forward secrecy; server key exposed)',
        "target_port": 8447,
        "encrypted_by": 'tls',
        "hint": 'tcpdump -w cap.pcap ; curl the key under /.well-known/backup/ ; Wireshark -> RSA keys list.',
        "flag": _flag('FLAG_C6', 'FLAG{no_ephemeral_means_retroactive_decryption}'),
    },
    "7": {
        "slug": 'logjam',
        "title": 'Logjam (export DHE, CVE-2015-4000)',
        "points": 25,
        "skill": 'Export-DHE downgrade & discrete log over a precomputed 512-bit group',
        "objective": 'The server accepts EXPORT-grade DHE suites (512-bit Diffie-Hellman group). From an on-path position, force the downgrade to this weak group — whose discrete log is precomputable once and for all — recover the session secret and decrypt the traffic to read the flag (session cookie).',
        "transport": 'TLS 1.2 (export DHE — 512-bit DH group, downgrade allowed)',
        "target_port": 8448,
        "encrypted_by": 'tls',
        "hint": 'testssl.sh --logjam ; nmap --script ssl-dh-params ; openssl s_client -cipher EXP ; precomputed discrete log.',
        "flag": _flag('FLAG_C7', 'FLAG{export_dh_512_is_precomputable}'),
    },
    "8": {
        "slug": 'ssl-strip',
        "title": 'SSL Stripping',
        "points": 20,
        "skill": 'MITM defense-in-depth (HSTS, RFC 6797)',
        "objective": 'The login page is reachable in cleartext (no HSTS, hard-coded HTTP link). Downgrade the victim from HTTPS to HTTP and capture the flag sent in cleartext.',
        "transport": 'HTTP 80 + HTTPS 8443 (no Strict-Transport-Security header)',
        "target_port": 8443,
        "encrypted_by": 'tls',
        "hint": "bettercap caplet 'hstshijack' ; sslstrip2 ; ARP spoofing gateway+victim.",
        "flag": _flag('FLAG_C8', 'FLAG{downgrade_then_read_in_cleartext}'),
    },
    "9": {
        "slug": 'poodle-sslv3',
        "title": 'POODLE (SSL 3.0, CVE-2014-3566)',
        "points": 25,
        "skill": 'CBC padding oracle & protocol obsolescence',
        "objective": 'The server accepts SSL 3.0 with CBC encryption. The flag is carried by a session cookie. Exploit the POODLE padding oracle to reconstruct the cookie byte by byte.',
        "transport": 'SSL 3.0 (CBC, downgrade allowed — TLS_FALLBACK_SCSV absent)',
        "target_port": 8444,
        "encrypted_by": 'tls',
        "hint": 'Force the SSLv3 fallback (openssl s_client -ssl3) ; CBC oracle PoC from an on-path position.',
        "flag": _flag('FLAG_C9', 'FLAG{sslv3_cbc_padding_is_an_oracle}'),
    },
    "10": {
        "slug": 'beast-tls10',
        "title": 'BEAST (TLS 1.0/CBC, CVE-2011-3389)',
        "points": 25,
        "skill": 'Predictable CBC IV (TLS 1.0), adaptive chosen-plaintext',
        "objective": 'The server only accepts TLS 1.0 with CBC suites: the initialization vectors are predictable (chained from one record to the next). The flag is carried by a session cookie. Exploit the BEAST attack (blockwise chosen-boundary) to reconstruct it.',
        "transport": 'TLS 1.0 (CBC, predictable IV — no 1/n-1 record splitting)',
        "target_port": 8446,
        "encrypted_by": 'tls',
        "hint": 'openssl s_client -tls1 ; BEAST PoC from an on-path position (block-boundary control).',
        "flag": _flag('FLAG_C10', 'FLAG{predictable_iv_enables_chosen_plaintext}'),
    },
    "11": {
        "slug": 'heartbleed',
        "title": 'Heartbleed (CVE-2014-0160)',
        "points": 20,
        "skill": 'Out-of-bounds memory disclosure (RFC 6520)',
        "objective": "The server uses a version of OpenSSL vulnerable to Heartbleed. The flag resides in the process's memory. Trigger an out-of-bounds read via the Heartbeat extension and recover it from the dump.",
        "transport": 'TLS 1.1/1.2 (OpenSSL 1.0.1f — vulnerable Heartbeat extension)',
        "target_port": 8445,
        "encrypted_by": 'memory',
        "hint": 'nmap --script ssl-heartbleed ; RFC 6520 PoC reading up to 64 KB per heartbeat.',
        "flag": _flag('FLAG_C11', 'FLAG{heartbeat_payload_length_unchecked}'),
    },
}


def flag_digest(flag: str) -> str:
    """Verification digest (SHA-256, fixed lab salt)."""
    return hashlib.sha256(("tp-tls::" + flag).encode()).hexdigest()


# Digest table served for verification (no flag is ever compared in cleartext).
FLAG_DIGESTS = {cid: flag_digest(c["flag"]) for cid, c in CHALLENGES.items()}


def by_slug(slug: str):
    """Return (id, challenge) for a given slug, or (None, None)."""
    for cid, c in CHALLENGES.items():
        if c["slug"] == slug:
            return cid, c
    return None, None
