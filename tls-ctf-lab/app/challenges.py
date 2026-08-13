"""
challenges.py — Définition déclarative des 11 challenges du TP « Sécurité HTTPS ».

Progression pédagogique (ordre de résolution recommandé) :

  ── Prise en main (outillage) ─────────────────────────────────────────────
  1. OpenSSL   : fabriquer/inspecter/vérifier un certificat X.509 à la main.
  2. Scapy     : renifler, disséquer, forger et émettre des paquets.
  ── Interception réseau ───────────────────────────────────────────────────
  3. MITM HTTP : intercepter un flux en clair (ARP spoofing + sniffing).
  ── Attaques TLS proprement dites ─────────────────────────────────────────
  4. Certificat auto-signé & MITM        (identité PKI)
  5. Fuite de clé privée                 (gestion des secrets, RSA-OAEP applicatif)
  6. Absence de forward secrecy          (échange RSA : déchiffrement a posteriori)
  7. Logjam (DHE export)                  (forward secrecy « imparfaite » : DH 512 bits)
  8. SSL stripping                       (politique de transport, HSTS)
  9. POODLE (SSL 3.0)                     (oracle de padding CBC)
 10. BEAST  (TLS 1.0)                     (IV prévisible, CBC — après POODLE)
 11. Heartbleed                          (implémentation, divulgation mémoire)

Chaque challenge décrit :
  - le vecteur pédagogique (couche attaquée : outillage, identité PKI, secret,
    forward secrecy, négociation de protocole, implémentation…) ;
  - le mode de livraison du flag (« encrypted_by ») :
      • tls        → flag en clair applicatif, protégé UNIQUEMENT par le
                     front-end TLS (volontairement cassable) placé devant ;
      • cleartext  → flag en clair, AUCUN TLS (challenge d'interception) ;
      • rsa-oaep   → blob chiffré applicatif (fuite de clé, C5) ;
      • memory     → flag résident en mémoire du processus (Heartbleed, C11) ;
      • cert       → flag embarqué dans le certificat X.509 servi (C1) ;
      • beacon     → flag émis/répondu sur le réseau par une balise Scapy (C2).
  - le port et le protocole exposés par la CIBLE ;
  - le flag et son empreinte (vérification à divulgation nulle côté portail).

NOTE DE CONCEPTION — les flags sont chargés depuis l'environnement afin de
pouvoir régénérer une instance « propre » par promotion / par étudiant sans
recompiler l'image (cf. README §Reproductibilité).
"""

import hashlib
import os

# Domaine d'identité utilisé par toutes les cibles (résolu en /etc/hosts du lab).
LAB_DOMAIN = os.environ.get("LAB_DOMAIN", "bank.tp.lan")


def _flag(env_key: str, default: str) -> str:
    return os.environ.get(env_key, default)


CHALLENGES = {
    # ─────────────────────────── Prise en main ──────────────────────────── #
    "0": {
        "slug": "recon",
        "title": "Reconnaissance réseau (nmap)",
        "points": 10,
        "skill": "Découverte réseau : balayage d'hôtes et de ports avec nmap",
        "objective": (
            "Avant d'attaquer, cartographiez le laboratoire. Avec nmap, balayez "
            "le sous-réseau du lab pour dresser l'inventaire des services des "
            "challenges suivants (couples IP:port de C1 à C11). Un service de "
            "reconnaissance est à découvrir sur un port non standard : son titre "
            "HTTP contient le flag."
        ),
        "transport": "TCP (découverte de services — aucun chiffrement)",
        "target_port": 9000,
        "encrypted_by": "recon",
        "hint": "nmap -sn 172.28.0.0/24 (hôtes vivants) ; nmap -p- -sV 172.28.0.20 ; le flag est dans le titre HTTP (--script http-title).",
        "flag": _flag("FLAG_C0", "FLAG{map_the_terrain_before_the_assault}"),
    },
    "1": {
        "slug": "openssl-warmup",
        "title": "Prise en main d'OpenSSL",
        "points": 10,
        "skill": "Manipulation X.509 : génération, inspection, vérification ASN.1",
        "objective": (
            "Récupérez le certificat auto-signé servi par la cible, inspectez-le "
            "et vérifiez SA PROPRE signature en suivant la procédure OpenSSL "
            "(parcours ASN.1, extraction du BIT STRING de signature, "
            "déchiffrement RSA par la clé publique, comparaison au condensat du "
            "corps). Le flag est embarqué dans un champ du certificat."
        ),
        "transport": "TLS 1.2 (certificat auto-signé à inspecter/vérifier)",
        "target_port": 8451,
        "encrypted_by": "cert",
        "hint": "openssl s_client -connect CIBLE:8451 -showcerts ; openssl x509 -text ; asn1parse.",
        "flag": _flag("FLAG_C1", "FLAG{asn1_walk_then_verify_the_signature}"),
    },
    "2": {
        "slug": "scapy-warmup",
        "title": "Prise en main de Scapy",
        "points": 10,
        "skill": "Sniff / dissection / forge / envoi de paquets avec Scapy",
        "objective": (
            "Une balise diffuse périodiquement un paquet UDP sur le réseau du "
            "laboratoire. Reniflez-la avec Scapy pour découvrir la consigne, "
            "puis FORGEZ et envoyez le paquet « magique » attendu par la cible : "
            "elle répondra alors par un paquet contenant le flag."
        ),
        "transport": "Balise UDP/8452 sur le segment L2 du lab (broadcast)",
        "target_port": 8452,
        "encrypted_by": "beacon",
        "hint": "sniff(filter='udp port 8452') ; puis send(IP()/UDP(dport=8452)/b'GIVE-FLAG').",
        "flag": _flag("FLAG_C2", "FLAG{sniff_dissect_craft_send}"),
    },
    # ───────────────────────── Interception réseau ──────────────────────── #
    "3": {
        "slug": "mitm-http",
        "title": "MITM contre HTTP (clair)",
        "points": 20,
        "skill": "Interception active : ARP spoofing + sniffing d'un flux HTTP",
        "objective": (
            "Le client-victime consulte son relevé en HTTP CLAIR (aucun TLS). "
            "Placez-vous en homme-du-milieu par empoisonnement ARP entre la "
            "victime et la cible, puis reniflez le flux : le flag transite en "
            "clair dans la réponse HTTP."
        ),
        "transport": "HTTP 80 en clair (aucun chiffrement de transport)",
        "target_port": 8453,
        "encrypted_by": "cleartext",
        "hint": "arpspoof / bettercap OU Scapy (ARP is-at) ; sniff filter 'tcp port 8453'.",
        "flag": _flag("FLAG_C3", "FLAG{cleartext_http_has_no_secrets}"),
    },
    # ─────────────────────── Attaques TLS proprement ────────────────────── #
    "4": {
        "slug": "self-signed-mitm",
        "title": "Certificat auto-signé & MITM",
        "points": 15,
        "skill": "Validation d'identité PKI (RFC 5280)",
        "objective": (
            "Le client « victime » interroge le flux sécurisé en acceptant "
            "n'importe quel certificat. Positionnez-vous en homme-du-milieu, "
            "présentez votre propre certificat auto-signé et lisez le flag."
        ),
        "transport": "TLS 1.2 (certificat auto-signé, non validé par le client)",
        "target_port": 8441,
        "encrypted_by": "tls",
        "hint": "bettercap / mitmproxy en transparent proxy ; ARP spoofing du client.",
        "flag": _flag("FLAG_C4", "FLAG{identity_without_pki_is_no_identity}"),
    },
    "5": {
        "slug": "private-key-leak",
        "title": "Fuite de clé privée",
        "points": 20,
        "skill": "Gestion des secrets & confidentialité persistante",
        "objective": (
            "Le front-end expose par erreur la clé privée du serveur dans un "
            "répertoire public. Le flag est publié sous forme de blob chiffré "
            "RSA-OAEP. Récupérez la clé, déchiffrez le blob."
        ),
        "transport": "TLS 1.2 (clé privée serveur exposée sous /.well-known/)",
        "target_port": 8442,
        "encrypted_by": "rsa-oaep",
        "hint": "curl https://CIBLE/.well-known/backup/server.key puis openssl pkeyutl -decrypt.",
        "flag": _flag("FLAG_C5", "FLAG{a_leaked_key_breaks_forward_secrecy}"),
    },
    "6": {
        "slug": "pfs-rsa-kx",
        "title": "Absence de forward secrecy (échange RSA)",
        "points": 25,
        "skill": "Forward secrecy : déchiffrement a posteriori d'un trafic à échange RSA",
        "objective": (
            "Le serveur négocie un ÉCHANGE DE CLÉS RSA (aucun ECDHE/DHE) : le "
            "secret pré-maître est chiffré sous la clé publique RSA du serveur, "
            "et non dérivé d'un éphémère. Enregistrez le trafic TLS chiffré de la "
            "victime, faites fuiter la clé privée du serveur (exposée), puis "
            "déchiffrez A POSTERIORI la capture pour lire le flag."
        ),
        "transport": "TLS 1.2 (échange RSA — aucune forward secrecy ; clé privée exposée)",
        "target_port": 8447,
        "encrypted_by": "tls",       # flag en clair applicatif SOUS le TLS enregistré
        "hint": "tcpdump -w cap.pcap ; curl la clé sous /.well-known/backup/ ; Wireshark → RSA keys list.",
        "flag": _flag("FLAG_C6", "FLAG{no_ephemeral_means_retroactive_decryption}"),
    },
    "7": {
        "slug": "logjam",
        "title": "Logjam (DHE export, CVE-2015-4000)",
        "points": 25,
        "skill": "Downgrade DHE export & logarithme discret sur groupe 512 bits précalculé",
        "objective": (
            "Le serveur accepte des suites DHE de qualité EXPORT (groupe "
            "Diffie-Hellman de 512 bits). En position d'homme-du-milieu, forcez "
            "la rétrogradation vers ce groupe faible — dont le logarithme discret "
            "est précalculable une fois pour toutes — récupérez le secret de "
            "session et déchiffrez le trafic pour lire le flag (cookie de session)."
        ),
        "transport": "TLS 1.2 (DHE export — groupe DH 512 bits, downgrade autorisé)",
        "target_port": 8448,
        "encrypted_by": "tls",       # flag (cookie) sous un DHE 512 bits cassable
        "hint": "testssl.sh --logjam ; nmap --script ssl-dh-params ; openssl s_client -cipher EXP ; log discret précalculé.",
        "flag": _flag("FLAG_C7", "FLAG{export_dh_512_is_precomputable}"),
    },
    "8": {
        "slug": "ssl-strip",
        "title": "SSL Stripping",
        "points": 20,
        "skill": "Défense en profondeur MITM (HSTS, RFC 6797)",
        "objective": (
            "La page d'authentification est atteignable en clair (aucun HSTS, "
            "lien HTTP en dur). Rétrogradez la victime de HTTPS vers HTTP et "
            "capturez le flag transmis en clair."
        ),
        "transport": "HTTP 80 + HTTPS 8443 (aucun en-tête Strict-Transport-Security)",
        "target_port": 8443,
        "encrypted_by": "tls",
        "hint": "bettercap caplet 'hstshijack' ; sslstrip2 ; ARP spoofing passerelle+victime.",
        "flag": _flag("FLAG_C8", "FLAG{downgrade_then_read_in_cleartext}"),
    },
    "9": {
        "slug": "poodle-sslv3",
        "title": "POODLE (SSL 3.0, CVE-2014-3566)",
        "points": 25,
        "skill": "Oracle de padding CBC & obsolescence protocolaire",
        "objective": (
            "Le serveur accepte SSL 3.0 avec un chiffrement CBC. Le flag est "
            "porté par un cookie de session. Exploitez l'oracle de padding "
            "POODLE pour reconstituer le cookie octet par octet."
        ),
        "transport": "SSL 3.0 (CBC, downgrade autorisé — TLS_FALLBACK_SCSV absent)",
        "target_port": 8444,
        "encrypted_by": "tls",
        "hint": "Forcer le repli SSLv3 (openssl s_client -ssl3) ; PoC oracle CBC en position MITM.",
        "flag": _flag("FLAG_C9", "FLAG{sslv3_cbc_padding_is_an_oracle}"),
    },
    "10": {
        "slug": "beast-tls10",
        "title": "BEAST (TLS 1.0/CBC, CVE-2011-3389)",
        "points": 25,
        "skill": "IV prévisible en CBC (TLS 1.0), texte clair choisi adaptatif",
        "objective": (
            "Le serveur n'accepte que TLS 1.0 avec des suites CBC : les vecteurs "
            "d'initialisation sont prévisibles (chaînés d'un enregistrement au "
            "suivant). Le flag est porté par un cookie de session. Exploitez "
            "l'attaque BEAST (blockwise chosen-boundary) pour le reconstituer."
        ),
        "transport": "TLS 1.0 (CBC, IV prévisible — pas de 1/n-1 record splitting)",
        "target_port": 8446,
        "encrypted_by": "tls",
        "hint": "openssl s_client -tls1 ; PoC BEAST en position MITM (contrôle de la frontière de bloc).",
        "flag": _flag("FLAG_C10", "FLAG{predictable_iv_enables_chosen_plaintext}"),
    },
    "11": {
        "slug": "heartbleed",
        "title": "Heartbleed (CVE-2014-0160)",
        "points": 20,
        "skill": "Divulgation mémoire hors-limites (RFC 6520)",
        "objective": (
            "Le serveur utilise une version d'OpenSSL vulnérable à Heartbleed. "
            "Le flag réside en mémoire du processus. Provoquez une lecture "
            "hors-limites via l'extension Heartbeat et récupérez-le dans le dump."
        ),
        "transport": "TLS 1.1/1.2 (OpenSSL 1.0.1f — extension Heartbeat vulnérable)",
        "target_port": 8445,
        "encrypted_by": "memory",
        "hint": "nmap --script ssl-heartbleed ; PoC RFC 6520 lisant jusqu'à 64 Ko par battement.",
        "flag": _flag("FLAG_C11", "FLAG{heartbeat_payload_length_unchecked}"),
    },
}


def flag_digest(flag: str) -> str:
    """Empreinte de vérification (SHA-256, sel fixe de TP)."""
    return hashlib.sha256(("tp-tls::" + flag).encode()).hexdigest()


# Table d'empreintes servie à la vérification (aucun flag n'est comparé en clair).
FLAG_DIGESTS = {cid: flag_digest(c["flag"]) for cid, c in CHALLENGES.items()}


def by_slug(slug: str):
    """Retourne (id, challenge) pour un slug donné, ou (None, None)."""
    for cid, c in CHALLENGES.items():
        if c["slug"] == slug:
            return cid, c
    return None, None
