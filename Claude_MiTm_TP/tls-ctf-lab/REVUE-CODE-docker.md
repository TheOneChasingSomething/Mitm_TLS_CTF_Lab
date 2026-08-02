# Revue de code — fichiers Docker du TP « Sécurité HTTPS »

> Document de relecture. Même esprit que les revues Ansible et Python. Ici, la
> difficulté propre à ce dépôt est que **plusieurs images sont volontairement
> obsolètes et vulnérables** (OpenSSL 1.0.1f, SSLv3, DHE export, TLS 1.0). La revue
> ne cherche donc pas à « corriger » ces vulnérabilités — ce serait détruire le
> sujet — mais à vérifier qu'elles sont **assumées, épinglées, confinées**, et que
> tout le *reste* (ce qui n'est pas le sujet du challenge) respecte les bonnes
> pratiques : utilisateur non-root, secrets injectables, surface minimale,
> reproductibilité.

## 1. Méthode : comment lire un Dockerfile pour une revue

Un Dockerfile se lit **de haut en bas comme une recette d'image**, mais une revue
efficace le lit selon **cinq axes** [1, 2] :

1. **Base (`FROM`)** — quelle image, quelle version, épinglée ou flottante ?
   C'est la question n°1 de sécurité *et* de reproductibilité. Ici, distinguer les
   bases **récentes et saines** (nginx, python-slim, debian:12) des bases
   **héritées et vulnérables par conception** (ubuntu:14.04, httpd:2.4.29) — ces
   dernières doivent être justifiées par un commentaire.
2. **Provisioning (`RUN`, `COPY`, `ADD`)** — que télécharge-t-on, depuis où, avec
   quelle intégrité ? Combien de couches ? Nettoie-t-on les caches ?
3. **Secrets (`ARG`, `ENV`)** — un flag/clé est-il injectable ou figé dans une
   couche ? À quel moment (build vs run) ?
4. **Identité d'exécution (`USER`)** — root ou compte dédié ? capacités requises ?
5. **Surface (`EXPOSE`, `CMD`/`ENTRYPOINT`)** — quel port, quel processus PID 1 ?

Règle transverse : **classer chaque anomalie** en *voulue-et-confinée* (le sujet
du challenge) ou *collatérale* (à corriger). Le tableau §2 applique cette grille.

Un relecteur garde aussi en tête les invariants du lab : les flags viennent de
l'environnement (rotation) ; les certificats sont générés au build par un
`gen-certs.sh` commun ; les images legacy ne doivent **jamais** être routables.

---

## 2. Vue d'ensemble : 14 images, trois familles

| Image | Base | Rôle | Nature |
|-------|------|------|--------|
| `app` (portail) | `python:3.12-slim` | Backend Flask/gunicorn | Saine, durcie |
| `victim-client` | `python:3.12-slim` | Victime rejouée | Saine, durcie |
| `attacker` | `debian:12-slim` | Poste d'attaque (mode 3) | Saine, outillée |
| `openssl-warmup` (C1) | `nginx:1.27-alpine` | Cert à inspecter | Saine + flag au cert |
| `scapy-warmup` (C2) | `python:3.12-slim` | Balise UDP | Saine + `NET_RAW` |
| `mitm-http` (C3) | `nginx:1.27-alpine` | HTTP clair | Clair **volontaire** |
| `self-signed` (C4) | `nginx:1.27-alpine` | Cert auto-signé | Saine base, cert non fiable **voulu** |
| `key-leak` (C5) | `nginx:1.27-alpine` | Clé exposée | Saine base, fuite **voulue** |
| `pfs-rsa` (C6) | `nginx:1.27-alpine` | Échange kRSA | Saine base, pas de PFS **voulu** |
| `logjam` (C7) | **`ubuntu:14.04`** | DHE export 512 | **Legacy vulnérable voulu** |
| `ssl-strip` (C8) | `nginx:1.27-alpine` | HTTP+HTTPS sans HSTS | Saine base, pas de HSTS **voulu** |
| `poodle` (C9) | **`httpd:2.4.29`** | SSLv3/CBC | **Legacy vulnérable voulu** |
| `beast` (C10) | `nginx:1.27-alpine` | TLS 1.0/CBC réactivé | Base saine, `SECLEVEL=0` **voulu** |
| `heartbleed` (C11) | **`ubuntu:14.04`** + OpenSSL 1.0.1f compilé | Divulgation mémoire | **Legacy vulnérable voulu** |

Lecture de revue : trois bases héritées (`ubuntu:14.04`, `httpd:2.4.29`) portent
l'essentiel du risque « par conception » ; toutes trois sont **commentées** et
justifiées dans leur Dockerfile. Les autres partent de bases **récentes** ; leur
vulnérabilité vient d'une *configuration* (front-end), pas de l'image.

---

## 3. Images saines et durcies (le « reste » qui doit être exemplaire)

### 3.1 `app/Dockerfile` (portail)

```dockerfile
4  FROM python:3.12-slim
6  ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
9  COPY requirements.txt . ; RUN pip install --no-cache-dir -r requirements.txt
12 COPY app.py challenges.py crypto_utils.py ./ ; COPY templates ; COPY static
16 RUN mkdir -p /data/keys && useradd -r -u 10001 lab && chown -R lab /srv /data
17 USER lab
19 EXPOSE 5000
21 CMD ["gunicorn","-w","2","-b","0.0.0.0:5000","app:app"]
```

Points de revue — **image exemplaire** :

- **L4** base `slim` épinglée en `3.12` (mineure). Bon compromis taille/fraîcheur.
  *Durcissement possible* : épingler un **digest** (`@sha256:…`) pour une
  reproductibilité stricte [2].
- **L9–10** `requirements.txt` copié **avant** le code → la couche
  d'installation des dépendances est **mise en cache** tant que les dépendances
  ne changent pas (ordre optimal des couches) [1]. `--no-cache-dir` réduit la
  taille. Les versions sont **épinglées** (Flask 3.0.3, cryptography 43.0.1,
  gunicorn 22.0.0) → reproductible. Très bien.
- **L16–17** création d'un **utilisateur système non-root** (`-r`, UID fixe
  10001) + `USER lab` → le conteneur ne tourne pas en root. **Bonne pratique
  majeure** [3]. UID fixe = permissions de volume prévisibles.
- **L21** PID 1 = **gunicorn** (pas le serveur de dev Flask) → correct pour la
  prod de lab. 2 *workers* (le commentaire note que le flag mémoire C5 reste
  résident *par worker* — cohérent avec `app.py`).
- *Manque mineur* : pas de `HEALTHCHECK` (la route `/healthz` existe pourtant) →
  l'ajouter fiabiliserait l'orchestration.

### 3.2 `victim-client/Dockerfile`

```dockerfile
1 FROM python:3.12-slim
4 COPY client.py .
5 RUN useradd -r -u 10002 victim && mkdir -p /data && chown victim /data
6 USER victim
7 CMD ["python","client.py"]
```

- Minimal et **non-root** (UID 10002). `client.py` n'a **aucune dépendance
  externe** (stdlib `urllib`/`ssl`) → pas de `pip install`, image minuscule.
  Excellent.
- *Point de revue* : `python` non qualifié en `CMD` (résout `python` du PATH) —
  acceptable sur base slim. Pas de `PYTHONUNBUFFERED` ici alors que `client.py`
  utilise `flush=True` partout → sorties correctes malgré tout ; l'ajouter serait
  cohérent avec l'image portail.

### 3.3 `attacker/Dockerfile` (mode 3)

```dockerfile
7  FROM debian:12-slim
9  RUN apt-get update && apt-get install -y --no-install-recommends \
       python3 python3-pip python3-scapy tcpdump tshark nmap dsniff \
       openssl curl ca-certificates iproute2 iputils-ping less nano vim-tiny \
     && rm -rf /var/lib/apt/lists/*
19 RUN … > /etc/motd
24 CMD ["sleep","infinity"]
```

- Base **récente** `debian:12-slim` (contrairement aux cibles legacy) : le poste
  d'attaque n'a aucune raison d'être vulnérable. Bon.
- **`--no-install-recommends`** + `rm -rf /var/lib/apt/lists/*` dans le **même
  `RUN`** → couche minimale, pas de cache APT résiduel. Bonne pratique [1].
- **Outils** : scapy, tcpdump, tshark, nmap, dsniff (arpspoof/sslstrip), openssl…
  cohérents avec les corrigés. Le commentaire (L16–17) précise que `NET_RAW` est
  accordé **au conteneur**, pas à l'étudiant sur l'hôte → rappel de revue utile.
- **L24** `CMD ["sleep","infinity"]` : le conteneur reste vivant, l'étudiant y
  entre par `docker exec` (via SSH ForceCommand). Idiome correct pour un conteneur
  « bastion ».
- *Point de revue sécurité* : **aucun `USER`** → l'étudiant est **root dans le
  conteneur** (nécessaire pour Scapy/raw sockets). Le confinement ne repose donc
  **pas** sur l'utilisateur mais sur l'isolation conteneur↔hôte (pas de socket
  Docker, réseau `internal`) — cf. revue Ansible §5.4. À garder cohérent : ne
  jamais monter `/var/run/docker.sock` dans cette image, et envisager
  `no-new-privileges`/seccomp au niveau compose pour contenir une évasion.

### 3.4 Cibles nginx récentes (C1, C4, C5, C6, C8) — base saine, config vulnérable

Toutes suivent le même patron :
```dockerfile
FROM nginx:1.27-alpine ; apk add --no-cache openssl ; COPY nginx.conf ;
COPY gen-certs.sh ; RUN sh /gen-certs.sh bank.tp.lan /etc/nginx/certs ; EXPOSE <port>
```
- **Base récente épinglée** (`nginx:1.27-alpine`) → l'image *elle-même* n'est pas
  vulnérable ; c'est la **configuration** (`nginx.conf` : cert auto-signé, absence
  de HSTS, suites kRSA…) qui porte le défaut du challenge. **C'est la bonne façon
  de faire** : on n'introduit pas de CVE d'infrastructure, on met en scène une
  *mauvaise configuration*.
- `apk add --no-cache` → pas de cache de paquets. Bien.
- **Certificat généré au build** par `gen-certs.sh` (commun). *Point de revue à
  ne pas oublier* : ce script shell n'est pas dans le périmètre de ce document,
  mais il **doit** être audité séparément (génération de clés, permissions des
  `.key`, éventuelle injection du flag C1). Le signaler comme dépendance de revue.
- *C5 `key-leak`* : l'image elle-même est banale ; la fuite est orchestrée par la
  config nginx + la route portail (cf. revue Python §3.6). L'image ne **contient**
  pas la clé (générée au run/volume) → bien.

### 3.5 `scapy-warmup/Dockerfile` (C2)

- Base `python:3.12-slim` **récente**. `scapy==2.5.0` **épinglé** ; `tcpdump`,
  `libpcap` pour la capture L2. `rm -rf` du cache dans le même `RUN`. Propre.
- **L9** `ENV FLAG_C2="…"` : flag en **variable d'environnement** avec défaut →
  surchargé au run. Bien (rotation).
- `EXPOSE 8452/udp` documente le protocole. Le commentaire rappelle le besoin de
  `NET_RAW/NET_ADMIN`. Cohérent.

---

## 4. Images legacy — vulnérables **par conception** (le sujet)

La revue vérifie ici quatre choses pour **chaque** image : (a) la base est
**épinglée** (pas de tag flottant) ; (b) un **commentaire** justifie l'obsolescence
et pointe le README ; (c) un **avertissement** « isolé / jamais routable » ; (d)
le flag reste **injectable**.

### 4.1 `logjam/Dockerfile` (C7 — `ubuntu:14.04`, Apache)

- **L3–5 / L7** : commentaire clair — Ubuntu 14.04 conservé car sa pile
  **OpenSSL 1.0.1f** embarque encore les suites **EXPORT** (DH 512) retirées par
  OpenSSL ≥ 1.0.2g. Avertissement « conteneur isolé uniquement ». **Conforme aux
  quatre critères.**
- `--no-install-recommends` + purge du cache. `a2enmod ssl proxy …` puis
  activation du vhost. `ENV FLAG_C7` injectable. `APACHE_*` (L26–28) requis par
  les scripts Ubuntu — correct.
- *Points de revue* : (a) `apt-get update` sur une distro **EOL** (14.04) : les
  dépôts peuvent être déplacés vers `old-releases.ubuntu.com` → **build fragile
  dans le temps** ; le README le mentionne mais un relecteur le classe en risque
  de **reproductibilité** (recommander une image de base archivée/pré-cuite via
  Packer). (b) Base `ubuntu:14.04` = **tag flottant** vers la dernière 14.04 ;
  épingler un **digest** fiabiliserait.

### 4.2 `poodle/Dockerfile` (C9 — `httpd:2.4.29`)

- **L1–6** : commentaire — image httpd **héritée** dont l'OpenSSL parle encore
  **SSLv3** ; avertissement « volontairement obsolète, jamais routable ».
  Conforme.
- Génère le cert, inclut `httpd-ssl.conf`, `ENV FLAG_C9` injectable. `EXPOSE 8444`.
- *Point de revue* : `httpd:2.4.29` est un **tag précis** (bon) mais ancien ; le
  build dépend de la disponibilité continue de ce tag sur Docker Hub → dépendance
  externe à surveiller (idem : pré-cuire via Packer pour l'archivage).

### 4.3 `beast/Dockerfile` (C10 — nginx récent, TLS 1.0 réactivé)

- **Cas intéressant** : base **récente** `nginx:1.27-alpine`, mais on **réactive**
  TLS 1.0/CBC via `openssl-lab.cnf` (`SECLEVEL=0`) et `OPENSSL_CONF`. Le
  commentaire (L3–6) prévient que si l'image de base a été compilée **sans** TLS
  1.0, il faut basculer sur une base héritée. **Honnête et bien documenté.**
- Utilise un `entrypoint.sh` + `nginx.conf.template` (substitution `gettext`) →
  le flag C10 est injecté dans le cookie **au démarrage**. Bon (rotation).
- *Point de revue* : dépend d'un `entrypoint.sh` et d'un `.cnf` **à auditer
  séparément** (le `SECLEVEL=0` et la liste de suites CBC y vivent). Le signaler.

### 4.4 `heartbleed/Dockerfile` (C11 — compilation d'OpenSSL 1.0.1f)

Le plus lourd et le plus sensible :
```dockerfile
8  FROM ubuntu:14.04
10 RUN apt-get install build-essential wget ca-certificates
16 RUN wget -q https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz \
    && tar xzf … && ./config --prefix=/opt/openssl-vuln shared \
    && make -j"$(nproc)" && make install_sw
23 COPY gen-certs.sh ; COPY entrypoint.sh ; ENV FLAG_C11 ; RUN gen-certs + chmod
30 ENTRYPOINT ["/entrypoint.sh"]
```
- **On compile** OpenSSL 1.0.1f (extension Heartbeat vulnérable) → matière du
  challenge. Commentaire + avertissement « jamais routable ». Conforme aux
  critères.
- *Points de revue notables* :
  - **Intégrité du téléchargement (L16)** : `wget` de l'archive OpenSSL **sans
    vérification de somme de contrôle / signature**. C'est un **vrai point de
    revue supply-chain** : même pour une version vulnérable *voulue*, on veut
    l'archive **authentique** (une archive altérée introduirait une *autre* faille
    non maîtrisée). **Recommandation** : vérifier le SHA-256 connu de
    `openssl-1.0.1f.tar.gz` avant `tar`. (Le fait que la faille soit voulue ne
    dispense pas d'authentifier la source.)
  - **Dépendance réseau au build** : `wget` vers openssl.org + `apt` sur 14.04 EOL
    → build **non hermétique** et fragile dans le temps → pré-cuire via Packer.
  - `make -j"$(nproc)"` : correct. `install_sw` (sans docs) : minimise.
  - **Pas de `USER`** → le service tourne en root. Pour une cible de lab isolée
    lançant `openssl s_server`, c'est courant, mais un relecteur le note (un compte
    dédié serait un plus, si `entrypoint.sh` le permet).
  - `entrypoint.sh` **à auditer séparément** (c'est lui qui écrit le flag dans la
    page servie → présence en mémoire).

---

## 5. Constats transverses

**Épinglage des versions** : applicatif Python **épinglé** (requirements + tags
d'images) ; bases legacy en **tags** (précis pour httpd, flottant pour
ubuntu:14.04). *Durcissement* : épingler des **digests** partout pour une
reproductibilité forte.

**Intégrité des téléchargements** : la clé GPG Docker (revue Ansible) **et**
l'archive OpenSSL (C11) sont récupérées **sans checksum** → seul vrai point
supply-chain du dépôt, à corriger même pour du code « vulnérable voulu ».

**Utilisateur non-root** : **respecté** pour les images saines (app UID 10001,
victim 10002) ; **absent** pour `attacker` (root nécessaire, confiné par
isolation) et pour les cibles legacy (root de service, isolé). Cohérent avec les
rôles, à documenter.

**Minimisation des couches / caches** : `--no-install-recommends`, `--no-cache-dir`,
`apk --no-cache`, `rm -rf /var/lib/apt/lists/*` dans le même `RUN` → **bien
appliqué** partout.

**Secrets injectables** : tous les flags proviennent d'`ENV`/`ARG` avec défaut →
rotation sans recompilation. `openssl-warmup` (C1) injecte le flag **dans le
certificat** via `ARG FLAG_C1` au build (donc figé dans l'image de C1 — cohérent
avec le scénario « flag dans le cert », mais implique de **rebuild** pour tourner
ce flag-là, contrairement aux autres injectés au run). Nuance à noter.

**Confinement** : chaque image legacy porte un avertissement « isolé / jamais
routable ». La revue confirme que la garantie technique associée
(réseau `internal`, pas de publication de ports) vit côté compose/Ansible — les
Dockerfiles, eux, **documentent** l'exigence. Bonne séparation.

**Reproductibilité** : les cibles legacy dépendent de ressources externes (dépôts
EOL, Docker Hub, openssl.org) → recommandation forte de **pré-cuire via Packer**
(`docker save`) et de distribuer les tarballs (mode `load`), déjà prévu dans le
dépôt.

**Dépendances hors périmètre à auditer séparément** : `gen-certs.sh` (tous),
`entrypoint.sh` (beast, heartbleed), `openssl-lab.cnf` (beast), les `*.conf`
nginx/apache/httpd. Ils portent une part de la logique vulnérable → à inclure dans
une revue dédiée « scripts shell & configurations serveur ».

---

## 6. Recommandations d'amélioration (durcissement, hors périmètre TP)

1. Vérifier le **SHA-256** de `openssl-1.0.1f.tar.gz` (C11) avant extraction, et
   la **somme** de la clé GPG Docker (revue Ansible) — authentifier les sources
   même pour du code volontairement vulnérable.
2. **Épingler par digest** (`@sha256:…`) les bases, en priorité les legacy
   (`ubuntu:14.04`, `httpd:2.4.29`) → immuniser contre la disparition/dérive des
   tags.
3. **Pré-cuire** les cibles legacy via Packer et distribuer en `docker load` →
   builds hermétiques, indépendants des dépôts EOL.
4. Ajouter un **`HEALTHCHECK`** aux images de service (la route `/healthz` existe).
5. Ajouter `PYTHONUNBUFFERED=1` à l'image victime (cohérence).
6. Étendre la revue aux **scripts shell et configurations serveur** associés
   (`gen-certs.sh`, `entrypoint.sh`, `*.conf`, `openssl-lab.cnf`).
7. Optionnel : compte de service non-root dans les cibles legacy si l'`entrypoint`
   le permet.

---

## Annexe A — Flashcards (revue Docker)

1. **Q :** Quelle est la question n°1 d'une revue de Dockerfile ?
   **R :** La **base `FROM`** : image, version, épinglée ou flottante — enjeu de
   sécurité *et* de reproductibilité.

2. **Q :** Comment distinguer une vulnérabilité *voulue* d'un défaut *collatéral*
   dans ce dépôt ?
   **R :** La *voulue* est **commentée, épinglée, confinée** et constitue le sujet
   du challenge ; la *collatérale* (ex. téléchargement sans checksum) n'apporte
   rien au scénario et doit être corrigée.

3. **Q :** Pourquoi copier `requirements.txt` avant le code applicatif ?
   **R :** Pour **mettre en cache** la couche d'installation des dépendances tant
   qu'elles ne changent pas (ordre optimal des couches).

4. **Q :** Quel est le seul vrai point *supply-chain* des Dockerfiles ?
   **R :** L'archive OpenSSL 1.0.1f (C11) — et la clé GPG Docker — **téléchargées
   sans vérification de somme** ; à authentifier même si la faille est voulue.

5. **Q :** Pourquoi les cibles nginx récentes ne sont-elles pas « vulnérables » au
   sens image ?
   **R :** La base est **saine et récente** ; c'est la **configuration**
   (`nginx.conf` : cert auto-signé, pas de HSTS, kRSA…) qui met en scène le défaut.

6. **Q :** Le conteneur `attacker` tourne en root : est-ce un défaut ?
   **R :** Non — root y est nécessaire (Scapy/raw sockets) ; le confinement repose
   sur l'**isolation conteneur↔hôte** (pas de socket Docker, réseau `internal`),
   pas sur l'utilisateur.

7. **Q :** Pourquoi pré-cuire les images legacy via Packer ?
   **R :** Elles dépendent de dépôts **EOL** et de ressources externes → builds
   fragiles ; `docker save`/`load` rend le déploiement **hermétique** et
   reproductible.

8. **Q :** Quelle particularité a l'injection du flag C1 par rapport aux autres ?
   **R :** C1 est injecté **au build** dans le **certificat** (`ARG FLAG_C1`) →
   figé dans l'image ; les autres flags sont injectés **au run** (`ENV`), donc
   rotables sans rebuild.

9. **Q :** Quels fichiers hors Dockerfile faut-il auditer pour compléter la revue ?
   **R :** `gen-certs.sh`, `entrypoint.sh` (beast/heartbleed), `openssl-lab.cnf`,
   et les `*.conf` nginx/apache — ils portent une part de la logique vulnérable.

10. **Q :** Que garantit un `USER` non-root dans les images app/victim ?
    **R :** Le service ne s'exécute pas avec les privilèges root du conteneur →
    réduction de l'impact d'une compromission applicative.

## Annexe B — Glossaire des acronymes

| Acronyme | Développé | Explication |
|----------|-----------|-------------|
| **EOL** | *End Of Life* | Fin de support (Ubuntu 14.04) → dépôts déplacés, builds fragiles. |
| **CVE** | *Common Vulnerabilities and Exposures* | Identifiant de faille (Logjam, POODLE, BEAST, Heartbleed). |
| **PID** | *Process IDentifier* | PID 1 = processus principal du conteneur (gunicorn, apache, entrypoint). |
| **UID** | *User IDentifier* | Identifiant numérique d'utilisateur (10001/10002 fixés pour les volumes). |
| **APT** | *Advanced Package Tool* | Gestionnaire de paquets Debian/Ubuntu (bases legacy). |
| **APK** | *Alpine Package Keeper* | Gestionnaire de paquets d'Alpine (bases nginx-alpine). |
| **HSTS** | *HTTP Strict Transport Security* | En-tête (RFC 6797) **absent** volontairement en C8 (SSL strip). |
| **DHE** | *Diffie–Hellman Ephemeral* | Échange éphémère ; en version **export** (512 bits) pour Logjam (C7). |
| **CBC** | *Cipher Block Chaining* | Mode par blocs vulnérable en SSLv3/TLS1.0 (POODLE C9, BEAST C10). |
| **TLS/SSL** | *Transport Layer Security / Secure Sockets Layer* | Protocoles de transport ; SSLv3/TLS1.0 rejoués pour C9/C10. |
| **kRSA** | *key-exchange RSA* | Échange de clés RSA (sans éphémère) → pas de PFS (C6). |
| **GPG** | *GNU Privacy Guard* | Signature du dépôt Docker (checksum manquant = point supply-chain). |
| **PFS** | *Perfect Forward Secrecy* | Confidentialité persistante ; absente en C6, faible en C7. |

---

## Références

[1] Docker, *Best practices for writing Dockerfiles* (ordre des couches, cache,
    `--no-install-recommends`), docs.docker.com.
[2] Docker, *Dockerfile reference* & *Image tags/digests pinning*,
    docs.docker.com.
[3] Center for Internet Security, *CIS Docker Benchmark* (utilisateur non-root,
    surface minimale, `no-new-privileges`).
[4] NIST SP 800-190, *Application Container Security Guide*.
[5] IETF, *RFC 6520 (Heartbeat/Heartbleed)*, *RFC 6797 (HSTS)*, *CVE-2014-0160*,
    *CVE-2014-3566 (POODLE)*, *CVE-2015-4000 (Logjam)*, *CVE-2011-3389 (BEAST)*.

---
*Revue de code à usage interne — ANSSI / CFSSI. Les images marquées « legacy /
vulnérable voulu » le sont **par conception pédagogique** ; elles ne doivent
exister que dans le réseau de laboratoire isolé, jamais sur un réseau routable.*
