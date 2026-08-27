"""
app.py — Portail du TP « Sécurité HTTPS ».

Application unique (le « site web vulnérable » du sujet) qui, pour chaque
challenge, expose TROIS surfaces :

  1. /c/<id>/flag-feed  — livraison du message chiffré contenant le flag.
     • transport « tls »      → renvoie le flag en clair applicatif ; la
                                confidentialité repose entièrement sur le
                                front-end TLS (volontairement cassable) placé
                                devant le portail par la cible.
     • transport « rsa-oaep » → renvoie un blob RSA-OAEP (challenge 2).
     • transport « memory »   → place le flag dans un tampon résident en
                                mémoire (challenge 5, Heartbleed) et renvoie une
                                bannière anodine.

  2. /c/<id>/start      — page + endpoint de démarrage prenant une IP de
     DESTINATION. L'IP doit appartenir au réseau de laboratoire (RFC 1918,
     allow-list LAB_CIDR) : le portail refuse toute adresse publique afin de ne
     jamais se comporter en lanceur d'attaque générique. Le démarrage arme le
     client-victime interne, qui génère alors du trafic vers l'IP fournie —
     trafic que l'étudiant interceptera.

  3. /c/<id>/verify     — formulaire de vérification du flag (comparaison à
     temps constant sur empreinte SHA-256, aucun flag comparé en clair).

Ce découpage reflète le modèle de menace : le portail n'est jamais « troué »
au sens applicatif ; ce sont les couches de TRANSPORT placées devant lui
(nginx auto-signé, apache SSLv3, openssl 1.0.1f…) qui portent la vulnérabilité.
"""

import hmac
import ipaddress
import json
import os
import secrets
import time

from flask import Flask, Response, abort, redirect, render_template, request, url_for

from challenges import CHALLENGES, FLAG_DIGESTS, LAB_DOMAIN, flag_digest
from crypto_utils import encrypt_flag, ensure_keypair

app = Flask(__name__)

# Réseau autorisé pour les IP de destination (défaut : plage privée du lab).
LAB_CIDR = os.environ.get("LAB_CIDR", "172.28.0.0/24")
VICTIM_QUEUE = os.environ.get("VICTIM_QUEUE", "/data/victim_jobs.jsonl")
CHALLENGE_ID = os.environ.get("CHALLENGE_ID")  # None sur le portail global

# Challenge 11 (Heartbleed) : le flag est délibérément maintenu en mémoire du
# processus, dans un tampon jamais renvoyé au client par le code applicatif.
_MEMORY_SECRET = CHALLENGES["11"]["flag"].encode() * 8


# --------------------------------------------------------------------------- #
# Utilitaires
# --------------------------------------------------------------------------- #
def _dest_ip_allowed(raw: str) -> bool:
    """N'autorise qu'une IP appartenant au réseau de laboratoire déclaré."""
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        return False
    net = ipaddress.ip_network(LAB_CIDR, strict=False)
    return ip in net and ip.is_private


def _enqueue_victim_job(cid: str, dest_ip: str) -> str:
    """Arme le client-victime : écrit un ordre de trafic dans une file partagée."""
    token = secrets.token_hex(8)
    job = {
        "token": token,
        "challenge": cid,
        "slug": CHALLENGES[cid]["slug"],
        "dest_ip": dest_ip,
        "port": CHALLENGES[cid]["target_port"],
        "mode": CHALLENGES[cid]["encrypted_by"],
        "ts": int(time.time()),
    }
    os.makedirs(os.path.dirname(VICTIM_QUEUE), exist_ok=True)
    with open(VICTIM_QUEUE, "a") as fh:
        fh.write(json.dumps(job) + "\n")
    return token


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return render_template("index.html", challenges=CHALLENGES, domain=LAB_DOMAIN)


@app.route("/c/<cid>")
def challenge(cid):
    if cid not in CHALLENGES:
        abort(404)
    return render_template("challenge.html", cid=cid, c=CHALLENGES[cid], domain=LAB_DOMAIN)


# --------------------------------------------------------------------------- #
# (1) Livraison du message chiffré contenant le flag
# --------------------------------------------------------------------------- #
@app.route("/c/<cid>/flag-feed")
def flag_feed(cid):
    if cid not in CHALLENGES:
        abort(404)
    c = CHALLENGES[cid]
    mode = c["encrypted_by"]

    if mode == "rsa-oaep":
        # Challenge 2 : protection applicative. Blob déchiffrable seulement avec
        # la clé privée (que le front-end expose par erreur).
        payload = {
            "scheme": "RSA-OAEP-SHA256",
            "ciphertext_b64": encrypt_flag(c["flag"]),
            "hint": "Private key exposed at /.well-known/backup/server.key",
        }
        return Response(json.dumps(payload, indent=2), mimetype="application/json")

    if mode == "memory":
        # Challenge 11 : le flag n'est JAMAIS renvoyé par cette route. Il vit dans
        # _MEMORY_SECRET et n'est exfiltrable que par la lecture hors-limites
        # Heartbleed du front-end OpenSSL vulnérable.
        _ = _MEMORY_SECRET  # maintenu référencé → résident en mémoire
        return Response("OK — heartbeat service active.\n", mimetype="text/plain")

    if mode == "cert":
        # Challenge 1 (prise en main OpenSSL) : le flag n'est PAS renvoyé ici ;
        # il est embarqué dans le certificat X.509 servi par la cible (champ OU).
        # L'étudiant doit récupérer et inspecter le certificat lui-même.
        return Response(
            "The flag is embedded in the X.509 certificate served by the target.\n"
            "Retrieve it, then inspect it:\n"
            "  openssl s_client -connect TARGET:{port} -showcerts </dev/null "
            "| openssl x509 -text -noout\n".format(port=c["target_port"]),
            mimetype="text/plain",
        )

    if mode == "beacon":
        # Challenge 2 (prise en main Scapy) : le flag est émis/répondu sur le
        # réseau par la balise Scapy de la cible, jamais par cette route HTTP.
        return Response(
            "The flag is not delivered here. Sniff the target's UDP/{port} "
            "beacon with Scapy, then reply with the expected magic packet to "
            "obtain the flag.\n".format(port=c["target_port"]),
            mimetype="text/plain",
        )

    if mode == "recon":
        # Challenge 0 (reconnaissance) : le flag n'est PAS distribué ici. Il est
        # porté par un service à découvrir au balayage nmap (titre HTTP). Les
        # adresses sont dérivées de LAB_CIDR → correctes en local (172.28.0.0/24)
        # comme en instance isolée (172.29.<i>.0/24).
        import ipaddress
        _net = ipaddress.ip_network(LAB_CIDR, strict=False)
        _recon = str(_net.network_address + 20)
        return Response(
            "The flag is not delivered here. Map the lab with nmap:\n"
            f"  nmap -sn {LAB_CIDR}                     # live hosts\n"
            f"  nmap -p- -sV {_recon}               # ports + versions of the recon service\n"
            f"  nmap -p9000 --script http-title {_recon}   # the flag is in the HTTP title\n"
            "Then build the IP:port inventory of the following challenges.\n",
            mimetype="text/plain",
        )

    # mode == "tls" ou "cleartext" : le flag est en clair applicatif.
    #  - "tls"       → sa confidentialité repose ENTIÈREMENT sur le front-end TLS
    #                  (volontairement cassable) placé devant le portail ;
    #  - "cleartext" → il n'y a AUCUN chiffrement de transport (challenge MITM
    #                  HTTP) : quiconque renifle le segment lit le flag.
    return Response(
        f"SECURE-FEED {c['slug']}\nflag={c['flag']}\n",
        mimetype="text/plain",
    )


# --------------------------------------------------------------------------- #
# (2) Démarrage du challenge sur une IP de destination
# --------------------------------------------------------------------------- #
@app.route("/c/<cid>/start", methods=["GET", "POST"])
def start(cid):
    if cid not in CHALLENGES:
        abort(404)
    c = CHALLENGES[cid]

    if request.method == "GET":
        return render_template("start.html", cid=cid, c=c, lab_cidr=LAB_CIDR)

    dest_ip = request.form.get("dest_ip", "")
    if not _dest_ip_allowed(dest_ip):
        return render_template(
            "start.html",
            cid=cid,
            c=c,
            lab_cidr=LAB_CIDR,
            error=(
                f"IP refused. Only private addresses of {LAB_CIDR} "
                "(the lab network) are allowed. The portal never attacks a "
                "target outside its scope."
            ),
        ), 400

    token = _enqueue_victim_job(cid, dest_ip)
    return render_template("start.html", cid=cid, c=c, lab_cidr=LAB_CIDR,
                           token=token, dest_ip=dest_ip)


# --------------------------------------------------------------------------- #
# (3) Vérification du flag
# --------------------------------------------------------------------------- #
@app.route("/c/<cid>/verify", methods=["GET", "POST"])
def verify(cid):
    if cid not in CHALLENGES:
        abort(404)
    c = CHALLENGES[cid]

    if request.method == "GET":
        return render_template("verify.html", cid=cid, c=c)

    submitted = request.form.get("flag", "").strip()
    ok = hmac.compare_digest(flag_digest(submitted), FLAG_DIGESTS[cid])
    return render_template(
        "verify.html",
        cid=cid,
        c=c,
        result="success" if ok else "failure",
        points=c["points"] if ok else 0,
    )


@app.route("/.well-known/backup/server.key")
def leaked_key():
    """Fuite VOLONTAIRE (challenge 5). Sert la clé privée RSA du portail.

    En mode LOCAL, la cible key-leak sert elle-même ce fichier depuis le volume
    partagé. En mode SALLE DE TP, le portail est sur la machine prof et le volume
    n'est pas partagé entre machines : la cible key-leak proxifie alors ce chemin
    vers le portail, qui expose la clé ici. Dans les deux cas, c'est la même
    mauvaise pratique mise en scène (un secret servi sous une arborescence
    publique). Route sans intérêt hors du laboratoire isolé.
    """
    key_dir = os.environ.get("KEY_DIR", "/data/keys")
    path = os.path.join(key_dir, "server.key")
    if not os.path.exists(path):
        ensure_keypair()  # garantit que la paire (donc le blob C5) existe
    with open(path, "rb") as fh:
        return Response(fh.read(), mimetype="application/x-pem-file")


@app.route("/healthz")
def healthz():
    return {"status": "ok", "challenge": CHALLENGE_ID}


if __name__ == "__main__":
    # En production de lab, le portail est servi derrière le front-end TLS de la
    # cible (nginx/apache/openssl). En clair ici : le TLS est terminé en amont.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
