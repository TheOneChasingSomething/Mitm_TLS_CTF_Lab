"""
client.py — Client-victime du laboratoire.
"""

import json
import os
import ssl
import subprocess
import time
import urllib.request

QUEUE = os.environ.get("VICTIM_QUEUE", "/data/victim_jobs.jsonl")
POLL = float(os.environ.get("POLL_SECONDS", "5"))
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


_NO_VICTIM = {"recon", "openssl-warmup", "scapy-warmup"}
_PLAINTEXT = {"ssl-strip", "mitm-http"}
_LEGACY = {"poodle-sslv3": "-ssl3", "beast-tls10": "-tls1"}
_LEGACY_OPENSSL = "/opt/openssl-vuln/bin/openssl"


def _legacy_replay_poodle(job: dict) -> None:
    """Rejeu spécifique POODLE (C9) avec padding dynamique dans l'URL."""
    ip, port, slug = job["dest_ip"], job["port"], job["slug"]
    proto = _LEGACY[slug]
    env = dict(os.environ, LD_LIBRARY_PATH="/opt/openssl-vuln/lib")
    
    reps = 30
    print(f"[victim] job {job['token']} ({slug}, legacy {proto}) → "
          f"{ip}:{port} ×{reps}", flush=True)
          
    for i in range(reps):
        padding = "A" * (i % 16)
        request = (f"GET /c/{job['challenge']}/flag-feed?pad={padding} HTTP/1.0\r\n"
                   f"Host: bank.tp.lan\r\n\r\n").encode()
                   
        try:
            subprocess.run(
                [_LEGACY_OPENSSL, "s_client", "-connect", f"{ip}:{port}", proto,
                 "-cipher", "AES128-SHA:AES256-SHA:DES-CBC3-SHA"],
                input=request, env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=6,
            )
        except Exception as exc:
            print(f"[victim] {exc}", flush=True)
            
        time.sleep(0.5)


def _legacy_replay(job: dict) -> None:
    """Rejeu standard pour BEAST (C10) ou autres slugs hérités."""
    ip, port, slug = job["dest_ip"], job["port"], job["slug"]
    proto = _LEGACY[slug]
    request = (f"GET /c/{job['challenge']}/flag-feed HTTP/1.0\r\n"
               f"Host: bank.tp.lan\r\n\r\n").encode()
    env = dict(os.environ, LD_LIBRARY_PATH="/opt/openssl-vuln/lib")
    reps = 30
    print(f"[victim] job {job['token']} ({slug}, legacy {proto}) → "
          f"{ip}:{port} ×{reps}", flush=True)
    for _ in range(reps):
        try:
            subprocess.run(
                [_LEGACY_OPENSSL, "s_client", "-connect", f"{ip}:{port}", proto,
                 "-cipher", "AES128-SHA:AES256-SHA:DES-CBC3-SHA"],
                input=request, env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=6,
            )
        except Exception as exc:
            print(f"[victim] {exc}", flush=True)
        time.sleep(1)


def _replay(job: dict) -> None:
    ip, port, mode, slug = job["dest_ip"], job["port"], job["mode"], job["slug"]
    if slug in _NO_VICTIM:
        print(f"[victim] job {job['token']} ({slug}) — pas de trafic victime "
              f"(interaction directe avec la cible).", flush=True)
        return
        
    # Aiguillage selon le slug ou le challenge
    if slug == "poodle-sslv3" or str(job.get("challenge")) in ("9", "C9"):
        _legacy_replay_poodle(job)
        return
    elif slug in _LEGACY:
        _legacy_replay(job)
        return

    scheme = "http" if slug in _PLAINTEXT else "https"
    url = f"{scheme}://{ip}:{port}/c/{job['challenge']}/flag-feed"
    
    ctx = _insecure_ctx(job.get("challenge"))
    
    reps = 30 if mode in ("tls", "cleartext") else 10
    print(f"[victim] job {job['token']} → {url} ×{reps}", flush=True)
    for _ in range(reps):
        try:
            with urllib.request.urlopen(url, timeout=4, context=ctx) as r:
                r.read()
        except Exception as exc:
            print(f"[victim] {exc}", flush=True)
        time.sleep(1)


def _standalone_loop() -> None:
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