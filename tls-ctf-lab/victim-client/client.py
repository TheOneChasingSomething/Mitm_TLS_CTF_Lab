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

# Executor identity. The SAME file runs in the victim container (ROLE=victim,
# the default) and in the server container (ROLE=server): each instance only
# runs the XSS jobs whose "target" matches its own role, so the portal's
# victim/server selector routes to the right container. See _run_xss().
ROLE = os.environ.get("VICTIM_ROLE", "victim")
NODE = os.environ.get("NODE_BIN", "node")
LAB_CIDR = os.environ.get("LAB_CIDR", "172.28.0.0/24")


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


# --------------------------------------------------------------------------- #
# XSS payload executor
# --------------------------------------------------------------------------- #
# Runs a student-authored JS payload IN THIS CONTAINER via Node. The payload is
# prefixed with a small harness exposing a lab-scoped LAB object. Every network
# helper refuses any host outside LAB_CIDR, mirroring the portal's own guardrail
# so the executor can never be pointed at a public target.
def _ip_in_lab(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(LAB_CIDR, strict=False)
    except ValueError:
        return False


_XSS_HARNESS = r"""
'use strict';
const cp = require('child_process');
const _SELF_IP = __SELF_IP__;
const _ROLE    = __ROLE__;
const _CIDR    = __CIDR__;
const _PREFIX  = _CIDR.split('/')[0].split('.').slice(0, 3).join('.') + '.';
function _hostInLab(u) {
  try { const h = new URL(u).hostname; return h === _SELF_IP || h.startsWith(_PREFIX); }
  catch (e) { return false; }
}
const LAB = {
  selfIp: _SELF_IP,
  role: _ROLE,
  log: (...a) => console.log('[payload]', ...a),
  // Lab-scoped fetch (Node >= 18 ships a global fetch).
  fetch: (u, o) => {
    if (!_hostInLab(u)) { console.log('[LAB] blocked non-lab URL:', u); return Promise.resolve(null); }
    return fetch(u, o).catch(e => console.log('[LAB] fetch error:', e.message));
  },
  // One legacy SSLv3 request through the vulnerable openssl already shipped in
  // this image — lets a payload drive real POODLE (C9) traffic from here.
  legacy: (ip, port, path, proto = '-ssl3') => {
    if (!(ip === _SELF_IP || ip.startsWith(_PREFIX))) { console.log('[LAB] blocked:', ip); return; }
    const req = 'GET ' + path + ' HTTP/1.0\r\nHost: bank.tp.lan\r\n\r\n';
    try {
      cp.execFileSync('/opt/openssl-vuln/bin/openssl',
        ['s_client', '-connect', ip + ':' + port, proto,
         '-cipher', 'AES128-SHA:AES256-SHA:DES-CBC3-SHA'],
        { input: req, env: Object.assign({}, process.env, { LD_LIBRARY_PATH: '/opt/openssl-vuln/lib' }),
          timeout: 6000, stdio: ['pipe', 'ignore', 'ignore'] });
    } catch (e) { /* connection churn is expected */ }
  },
  loop: async (n, fn) => { for (let i = 0; i < n; i++) { await fn(i); } }
};
// Minimal browser-ish shims so simple DOM-style payloads do not hard-crash.
globalThis.LAB = LAB;
globalThis.window = globalThis;
globalThis.document = { cookie: '', write: s => console.log('[document.write]', s),
  getElementById: () => ({ textContent: '', innerHTML: '' }), createElement: () => ({}) };
globalThis.alert = m => console.log('[alert]', m);
"""


def _run_xss(job: dict) -> None:
    # Only the executor whose ROLE matches the job's target runs it.
    if job.get("target", "victim") != ROLE:
        return
    ip = job.get("dest_ip", "")
    payload = job.get("payload", "")
    token = job.get("token", "?")
    if not _ip_in_lab(ip):
        print(f"[{ROLE}] xss job {token} refused: {ip} outside {LAB_CIDR}", flush=True)
        return
    print(f"[{ROLE}] xss job {token} → executing student JS in Node "
          f"(LAB.selfIp={ip})", flush=True)
    harness = (_XSS_HARNESS
               .replace("__SELF_IP__", json.dumps(ip))
               .replace("__ROLE__", json.dumps(ROLE))
               .replace("__CIDR__", json.dumps(LAB_CIDR)))
    program = harness + "\n// ==== injected payload ====\n" + payload + "\n"
    try:
        subprocess.run([NODE, "-e", program], timeout=30)
    except FileNotFoundError:
        print(f"[{ROLE}] node not found — install nodejs in this container "
              f"to run XSS payloads.", flush=True)
    except Exception as exc:
        print(f"[{ROLE}] xss exec error: {exc}", flush=True)


def _dispatch(job: dict) -> None:
    """Route a queued job: XSS payloads to the JS executor, everything else to
    the traffic replayer."""
    if job.get("type") == "xss":
        _run_xss(job)
    else:
        _replay(job)


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
            _dispatch(job)
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
                        _dispatch(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        time.sleep(POLL)


def main() -> None:
    print(f"[{ROLE}] client-victime démarré (role={ROLE}).", flush=True)
    if MODE == "standalone":
        _standalone_loop()
    else:
        _queue_loop()


if __name__ == "__main__":
    main()