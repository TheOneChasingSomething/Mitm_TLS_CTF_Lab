"""
client.py — Client-victime du laboratoire.

Rôle pédagogique : jouer la « victime » naïve dont l'étudiant interceptera le
trafic. Il consomme la file de jobs alimentée par le portail (bouton
« Démarrer » → IP de destination) et, selon le challenge, interroge la cible
d'une manière volontairement imprudente :

  mitm-http      : consulte son relevé en HTTP CLAIR → reniflable tel quel.
  self-signed    : HTTPS en DÉSACTIVANT la validation du certificat (verify=False)
                   → interceptable par un MITM présentant son propre certificat.
  pfs-rsa-kx     : ouvre des sessions TLS à ÉCHANGE RSA (sans éphémère) → le
                   trafic enregistré est déchiffrable a posteriori si la clé fuit.
  logjam         : sessions TLS rétrogradables vers un DHE export (512 bits) →
                   secret éphémère cassable par logarithme discret précalculé.
  ssl-strip      : suit un lien HTTP en clair → rétrogradable / lisible en clair.
  poodle / beast : négocient SSLv3 / TLS 1.0 CBC et rejouent la requête
                   → matière première de l'oracle de padding / du chosen-plaintext.
  heartbleed     : ouvre des sessions TLS régulières → maintient des secrets en
                   mémoire côté serveur, exfiltrables par Heartbleed.

  Les warm-ups OpenSSL et Scapy ne génèrent aucun trafic victime (interaction
  directe de l'étudiant avec la cible).

⚠️ La désactivation de la vérification TLS ci-dessous est INTENTIONNELLE et
   circonscrite au laboratoire isolé. Ne jamais reproduire en production.
"""

import json
import os
import ssl
import time
import urllib.request

QUEUE = os.environ.get("VICTIM_QUEUE", "/data/victim_jobs.jsonl")
POLL = float(os.environ.get("POLL_SECONDS", "5"))
# Mode d'armement :
#   "queue"      → (local) consomme la file de jobs écrite par le portail via le
#                  volume partagé ; l'étudiant arme chaque challenge via /start.
#   "standalone" → (salle de TP) aucune file partagée entre machines : la victime
#                  rejoue en boucle une liste statique de cibles LOCALES fournie
#                  par VICTIM_STANDALONE_TARGETS (JSON), de sorte qu'un flux à
#                  intercepter circule en permanence sans armement central.
MODE = os.environ.get("VICTIM_MODE", "queue")
STANDALONE_TARGETS = os.environ.get("VICTIM_STANDALONE_TARGETS", "[]")
_seen = set()


def _insecure_ctx(challenge: str | int = "") -> ssl.SSLContext:
    """Contexte TLS victime : accepte n'importe quel certificat (faille C1)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    if str(challenge) == "6":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers('AES128-SHA:@SECLEVEL=1')

        print("[victim] TLS VERSION:", ctx.minimum_version, ctx.maximum_version)

        print(
            "[victim] ENABLED CIPHERS:",
            ":".join(c["name"] for c in ctx.get_ciphers()),
            flush=True
        ) 
    return ctx


# Les warm-ups (OpenSSL, Scapy) sont des exercices d'interaction DIRECTE avec la
# cible : aucun trafic victime à générer.
_NO_VICTIM = {"recon", "openssl-warmup", "scapy-warmup"}
# Challenges dont le trafic victime circule en HTTP clair (interceptable tel quel).
_PLAINTEXT = {"ssl-strip", "mitm-http"}


def _replay(job: dict) -> None:
    ip, port, mode, slug = job["dest_ip"], job["port"], job["mode"], job["slug"]  #[cite: 7]
    if slug in _NO_VICTIM:  #[cite: 7]
        print(f"[victim] job {job['token']} ({slug}) — pas de trafic victime "  #[cite: 7]
              f"(interaction directe avec la cible).", flush=True)  #[cite: 7]
        return  #[cite: 7]
    scheme = "http" if slug in _PLAINTEXT else "https"  #[cite: 7]
    url = f"{scheme}://{ip}:{port}/c/{job['challenge']}/flag-feed"  #[cite: 7]
    
    # Validation du contexte via le champ challenge (int ou str)
    ctx = _insecure_ctx(job.get("challenge"))
    
    reps = 30 if mode in ("tls", "cleartext") else 10  #[cite: 7]
    print(f"[victim] job {job['token']} → {url} ×{reps}", flush=True)  #[cite: 7]
    for _ in range(reps):  #[cite: 7]
        try:  #[cite: 7]
            with urllib.request.urlopen(url, timeout=4, context=ctx) as r:  #[cite: 7]
                r.read()  #[cite: 7]
        except Exception as exc:  #[cite: 7]
            print(f"[victim] {exc}", flush=True)  #[cite: 7]
        time.sleep(1)  #[cite: 7]


def _standalone_loop() -> None:
    """Mode salle de TP : rejoue en boucle une liste statique de cibles locales.

    VICTIM_STANDALONE_TARGETS est un JSON de jobs (mêmes champs que la file du
    portail) : [{"challenge","slug","dest_ip","port","mode","token"}, …].
    dest_ip peut être un NOM DE SERVICE docker (résolu localement), la cible
    étant sur la même machine que la victime.
    """
    try:
        jobs = json.loads(STANDALONE_TARGETS)
    except json.JSONDecodeError:
        jobs = []
    print(f"[victim] mode STANDALONE (salle de TP) — {len(jobs)} cible(s) locale(s) "
          f"rejouée(s) en boucle.", flush=True)
    while True:
        for job in jobs:
            job.setdefault("token", "standalone")
            _replay(job)
        time.sleep(POLL)


def _queue_loop() -> None:
    """Mode local : consomme la file de jobs armée par le portail (/start)."""
    print("[victim] mode QUEUE (local) — en attente d'ordres du portail…", flush=True)
    while True:
        if os.path.exists(QUEUE):
            with open(QUEUE) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line in _seen:
                        continue
                    _seen.add(line)
                    try:
                        _replay(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        time.sleep(POLL)


def main() -> None:
    print("[victim] client-victime démarré.", flush=True)
    if MODE == "standalone":
        _standalone_loop()
    else:
        _queue_loop()


if __name__ == "__main__":
    main()
