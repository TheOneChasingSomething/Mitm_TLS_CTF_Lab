# Revue de code — Python du TP « Sécurité HTTPS »

> Document de relecture. Même esprit que la revue Ansible : expliquer *comment lire*
> le code Python du laboratoire pour en conduire la revue, puis détailler chaque
> fichier en séparant ce que fait le code de ce qu'un relecteur doit **vérifier**.
> Particularité de ce dépôt : une partie des « défauts » est **intentionnelle et
> pédagogique** (contextes TLS permissifs, secrets servis à dessein). La revue doit
> donc distinguer *vulnérabilité voulue et confinée* de *défaut collatéral non
> maîtrisé* — c'est le fil directeur.

## 1. Méthode : dans quel ordre lire ce code

Le Python se répartit en trois familles de responsabilité, à lire dans cet ordre
[1] :

1. **Le modèle de données** — `app/challenges.py` : la définition déclarative des
   11 challenges (le *quoi*). Tout part de là : ports, modes de livraison des
   flags, empreintes de vérification. Le relire en premier donne la grille de
   lecture de tout le reste.
2. **Le portail** — `app/app.py` + `app/crypto_utils.py` : le service Flask qui
   expose les surfaces (livraison, armement, vérification). C'est le composant
   exposé au réseau → cœur de la revue de sécurité applicative.
3. **Les acteurs de trafic** — `victim-client/client.py` (la victime rejouée) et
   `targets/scapy-warmup/beacon.py` (la cible balise). Ils *génèrent* le trafic
   que l'étudiant intercepte.
4. **Les corrigés** — `solutions/scapy/*.py` : code offensif de référence
   (ARP spoofing, sniffing, solveur Scapy). À relire pour vérifier qu'ils sont
   corrects, sobres, et **non distribués aux étudiants** dans les images.

Règle transverse : **suivre le flag**. Un flag naît d'une variable
d'environnement (`FLAG_Cn`), transite en clair applicatif ou sous une forme
chiffrée, et n'est vérifié que par **empreinte**. Tracer ce cheminement révèle où
un secret pourrait fuir *hors* du scénario prévu.

Points de contrôle génériques Python [2, 3] : validation des entrées externes
(tout ce qui vient de `request`, de l'environnement, du réseau) ; gestion des
exceptions (trop large = masque des bugs) ; opérations de fichiers concurrentes ;
comparaisons de secrets à temps constant ; et surface réseau (bind, ports,
workers).

---

## 2. `app/challenges.py` — le modèle de données

Rôle : source unique de vérité des challenges. Aucune logique réseau, que des
données + trois fonctions utilitaires.

- **L44** `LAB_DOMAIN` lu depuis l'environnement (défaut `bank.tp.lan`).
- **L47–48** `_flag(env_key, default)` : chaque flag est lu depuis
  l'environnement, avec un défaut. **Choix de conception clé** (documenté L35–37) :
  permet de faire tourner les flags par promotion/étudiant sans recompiler. La
  revue valide que **tous** les challenges suivent ce motif (c'est le cas :
  `_flag("FLAG_Cn", …)` partout).
- **L51–240** dictionnaire `CHALLENGES` : pour chacun, `slug`, `points`,
  `encrypted_by` (le mode de livraison), `target_port`, `flag`. Points de revue :
  - **Cohérence `encrypted_by` ↔ traitement** : chaque valeur (`cert`, `beacon`,
    `cleartext`, `tls`, `rsa-oaep`, `memory`) doit être gérée dans `app.py`
    (§3). Un mode orphelin tomberait dans la branche par défaut « clair
    applicatif » — à vérifier par recoupement (fait en §3, la correspondance est
    complète).
  - **Unicité des ports** : 8451, 8452, 8453, 8441, 8442, 8447, 8448, 8443,
    8444, 8446, 8445 — aucun doublon. Bon.
  - **Les flags par défaut sont en clair dans le source.** Ils sont *descriptifs*
    (ex. `FLAG{sslv3_cbc_padding_is_an_oracle}`) et servent de repli hors
    déploiement. Comme ils sont surchargés par l'environnement en production de
    lab (via Ansible/compose), ce n'est pas un secret durci — mais un relecteur
    note que le *défaut* ne doit jamais être considéré comme confidentiel.
- **L243–245** `flag_digest` : `sha256("tp-tls::" + flag)`. **Point de revue
  cryptographique important.** C'est un condensat **salé par une constante fixe**,
  pas un HMAC ni un hash lent. Pour un usage de TP (vérifier qu'un étudiant a
  trouvé un flag public), c'est acceptable ; mais si les flags devaient rester
  secrets, un sel fixe + SHA-256 rapide serait vulnérable à un dictionnaire. À
  documenter comme choix assumé (les flags ne sont pas des secrets à protéger, ils
  sont *à trouver*).
- **L249** `FLAG_DIGESTS` : table d'empreintes précalculée → la vérification ne
  manipule jamais le flag en clair. Bonne propriété (voir `verify` en §3).
- **L252–257** `by_slug` : recherche linéaire (11 entrées → négligeable).

---

## 3. `app/app.py` — le portail Flask

Le docstring (L1–30) énonce le **modèle de menace** : le portail n'est jamais
« troué » au sens applicatif ; ce sont les couches de **transport** placées devant
lui qui portent la vulnérabilité. Un relecteur garde cet invariant comme critère :
toute fuite applicative *non prévue* serait un défaut.

### 3.1 Configuration et état (L44–53)

- **L47** `LAB_CIDR` (défaut `172.28.0.0/16`) : réseau autorisé pour les IP de
  destination — pierre angulaire du garde-fou anti-abus (§3.3).
- **L53** `_MEMORY_SECRET = CHALLENGES["11"]["flag"].encode() * 8` : le flag C11
  est **délibérément maintenu résident** en mémoire (matière première de
  Heartbleed). **Vérification de cohérence** : ce secret ne doit être renvoyé par
  *aucune* route — confirmé, la route `flag-feed` en mode `memory` renvoie une
  bannière anodine (L122–127). C'est le point le plus sensible à auditer : le
  scénario Heartbleed repose sur le fait que le flag vit en mémoire mais n'est
  jamais servi par le code.

### 3.2 Livraison du flag — `flag_feed` (L105–159)

Aiguillage selon `encrypted_by`. La revue vérifie **chaque branche** :

- `rsa-oaep` (C5) : renvoie un blob chiffré + un *hint* pointant la clé exposée.
  Le flag n'est jamais en clair ici. Correct.
- `memory` (C11) : ne renvoie **pas** le flag (voir §3.1). Correct.
- `cert` (C1) / `beacon` (C2) : renvoient une **consigne**, pas le flag (il est
  dans le certificat / émis par la balise). Correct.
- défaut `tls`/`cleartext` (L156–159) : renvoie `flag=<flag>` en **clair
  applicatif**. **C'est voulu** : en `tls`, la confidentialité repose sur le
  front-end TLS cassable ; en `cleartext`, il n'y a aucun chiffrement (challenge
  d'interception). La revue confirme que cette route n'est atteignable que *via*
  la cible (le portail est sur réseau interne, pas publié directement en mode
  salle) — sinon le flag serait lisible sans attaque. **Point d'attention
  déploiement** : ne jamais publier le port du portail directement côté étudiant.

### 3.3 Armement — `start` (L165–190)

- **L174–175** lit `dest_ip` du formulaire et le valide par `_dest_ip_allowed`.
- **L59–66** `_dest_ip_allowed` : parse l'IP (rejet si invalide), vérifie
  qu'elle appartient à `LAB_CIDR` **et** qu'elle est privée (`ip.is_private`).
  **Très bon réflexe de conception** : le portail refuse de générer du trafic
  vers une adresse publique → il ne peut pas servir de lanceur d'attaque / SSRF
  générique [4]. Points de revue :
  - La double condition (`in net` **et** `is_private`) est une défense en
    profondeur : même si `LAB_CIDR` était mal configuré en plage publique,
    `is_private` bloquerait. Bien.
  - `raw.strip()` gère les espaces ; les entrées non-IP lèvent `ValueError` →
    `False`. Robust.
  - **Résidus à considérer** : pas de gestion explicite d'IPv6 (le lab est IPv4 ;
    une entrée IPv6 privée passerait `is_private` mais échouerait probablement
    `in net` si `LAB_CIDR` est IPv4 — comportement sûr par défaut). À documenter.
- **L188** en cas de succès, `_enqueue_victim_job` écrit un ordre ; renvoie un
  `token`.

### 3.4 File d'armement — `_enqueue_victim_job` (L69–84)

- Construit un job JSON (token aléatoire `secrets.token_hex(8)`, challenge, slug,
  dest_ip, port, mode, timestamp) et l'**ajoute** (`"a"`) à
  `VICTIM_QUEUE` (`/data/victim_jobs.jsonl`, un JSON Lines).
- **Points de revue** :
  - **Concurrence** : plusieurs workers gunicorn (le Dockerfile en lance 2)
    écrivent dans le même fichier. L'`append` d'une ligne courte est *en général*
    atomique sous POSIX si < PIPE_BUF, mais **rien ne le garantit** ici pour des
    lignes JSON de taille variable. Un relecteur signale l'absence de verrou
    (`fcntl.flock`) → risque théorique d'entrelacement. En pratique, volumétrie
    de TP négligeable, mais à noter.
  - `os.makedirs(..., exist_ok=True)` avant écriture : idempotent, bien.
  - Le job n'est jamais purgé (fichier append-only) → croissance illimitée sur un
    lab longue durée. Mineur ; une rotation serait un plus.

### 3.5 Vérification — `verify` (L196–213)

- **L205–206** : `hmac.compare_digest(flag_digest(submitted), FLAG_DIGESTS[cid])`.
  **Excellent** : comparaison **à temps constant** sur des **empreintes**, jamais
  sur le flag en clair → ni timing attack exploitable, ni flag en clair en
  mémoire de comparaison [5]. C'est la bonne pratique de référence pour un
  contrôle de secret. Rien à redire.
- Pas de limitation de débit (rate-limiting) sur `verify` : un étudiant pourrait
  brute-forcer. Mais les flags ont un espace de recherche gigantesque
  (chaînes descriptives) → non exploitable. Mention pour exhaustivité.

### 3.6 Fuite volontaire — `leaked_key` (L216–232)

- Sert la **clé privée RSA** du portail sous `/.well-known/backup/server.key`.
  C'est la **vulnérabilité mise en scène** de C5 (secret sous arborescence
  publique). Le docstring explique le double comportement local vs salle (proxy).
- **Points de revue** :
  - **Path traversal** : le chemin est construit par
    `os.path.join(key_dir, "server.key")` avec un nom **en dur** — aucune entrée
    utilisateur → pas de traversée possible. Bien.
  - Si le fichier manque, `ensure_keypair()` le crée → la route est
    auto-suffisante.
  - **Le vrai risque de revue n'est pas le code mais le déploiement** : cette
    route ne doit exister **que** dans l'instance de lab isolée. Elle est inerte
    hors périmètre (personne ne devrait joindre le portail), mais un relecteur
    exige qu'elle ne soit **jamais** compilée dans une image exposée hors lab.
    C'est le pendant applicatif de la règle « images legacy jamais routables ».

### 3.7 Exposition du service (L235–243)

- `/healthz` (L235) : sonde de vivacité, renvoie l'ID de challenge. Sans risque.
- **L243** `app.run(host="0.0.0.0", …)` : bind sur **toutes** les interfaces.
  Normal en conteneur (réseau isolé). **Attention** : ce `app.run` n'est utilisé
  qu'en exécution directe ; en production de lab, c'est **gunicorn** qui sert
  (Dockerfile). Le relecteur note que le serveur de développement Flask ne doit
  pas être le serveur de production — ici respecté.

---

## 4. `app/crypto_utils.py` — RSA-OAEP (C5)

- **L25–48** `ensure_keypair` : charge la paire RSA depuis `/data/keys`, ou la
  génère (RSA-2048, e=65537). Écrit la clé privée **sans chiffrement**
  (`NoEncryption`) — **volontaire** (elle *doit* fuiter pour C5). En dehors du
  scénario, ce serait un défaut ; ici c'est le sujet même du challenge.
- **L51–62** `encrypt_flag` : RSA-**OAEP** avec MGF1-SHA256 et hash SHA-256.
  **Bon choix** : OAEP est le *padding* asymétrique sûr (résistant à
  Bleichenbacher, contrairement à PKCS#1 v1.5) [6]. La revue valide que le
  challenge illustre « fuite de clé », pas « padding faible » — cohérent : le
  chiffrement est correct, c'est la *gestion de la clé* qui est le défaut
  pédagogique.
- **Points de revue** :
  - Clé de 2048 bits : conforme aux recommandations actuelles (≥ 2048) [7].
  - `ensure_keypair` est appelée par plusieurs chemins (feed C5, leaked_key) :
    idempotente et sûre en relecture (création atomique par
    `open(..,"wb")`, pas de course destructive puisque le premier arrivé écrit).
    Un verrou serait un plus si N workers généraient simultanément au tout
    premier démarrage — risque limité (écriture unique au boot).

---

## 5. `victim-client/client.py` — la victime rejouée

Le docstring (L1–27) est explicite : ce client joue la **victime naïve** et la
désactivation de la validation TLS est **intentionnelle et circonscrite**. La
revue vérifie surtout que cette imprudence reste **cantonnée** au bon usage.

- **L44–45** `MODE` (`queue`/`standalone`) et `STANDALONE_TARGETS` (JSON) : les
  deux modes d'armement. Bien séparés.
- **L49–54** `_insecure_ctx` : `check_hostname=False`, `verify_mode=CERT_NONE`.
  **C'est la faille pédagogique** (la victime accepte tout certificat → MITM
  possible). Point de revue : cette imprudence est-elle **bornée** aux challenges
  qui l'exigent ? Elle est appliquée à **tout** trafic HTTPS de la victime
  (L72). C'est acceptable ici car *toute* la victime est un cobaye, mais un
  relecteur le note : le contexte permissif n'est pas discriminé par challenge.
- **L59/61** `_NO_VICTIM` (warm-ups → pas de trafic) et `_PLAINTEXT`
  (`ssl-strip`, `mitm-http` → HTTP clair). La revue recoupe avec `challenges.py` :
  les modes concordent.
- **L64–81** `_replay` : construit l'URL (`http` vs `https` selon le slug),
  boucle 10–30 fois, lit la réponse. **Points de revue** :
  - **L79** `except Exception` (noqa BLE001) : capture **très large**. Justifiée
    et **assumée** (commentaire « lab : on ignore les erreurs réseau ») car la
    victime doit survivre à une cible momentanément absente. En code de
    production ce serait un défaut ; ici c'est un choix documenté. Bon réflexe
    d'avoir annoté le `noqa` avec la raison.
  - **L65** accès direct `job["dest_ip"]`, etc. : si un job malformé arrivait
    (clé manquante), `KeyError` non capturé **dans `_replay`** — mais l'appelant
    `_queue_loop` (L116–119) n'entoure `_replay` que d'un `JSONDecodeError`.
    Un job JSON valide mais **incomplet** ferait planter la boucle. **À
    signaler** : robustesse perfectible (valider les clés attendues, ou élargir
    le `try`). En `standalone`, les jobs sont statiques et contrôlés → risque
    nul ; en `queue`, ils viennent du portail (contrôlés aussi) → risque faible,
    mais la validation défensive manquante est un vrai point de revue.
  - `timeout=4` sur chaque requête : évite le blocage. Bien.
- **L84–102** `_standalone_loop` : lit `STANDALONE_TARGETS`, rejoue en boucle.
  `json.loads` entouré d'un `JSONDecodeError` → dégrade proprement en liste vide.
  Bon.
- **L105–120** `_queue_loop` : relit le fichier file **entièrement** à chaque
  tour, dédoublonne via l'ensemble `_seen` (la ligne brute sert de clé). **Points
  de revue** :
  - `_seen` croît indéfiniment (une entrée par job vu) → fuite mémoire lente sur
    un lab très long. Négligeable en TP.
  - Relire tout le fichier à chaque `POLL` est O(n) cumulatif ; volumétrie de TP
    → sans impact.
  - Pas de gestion si le fichier est tronqué en cours d'écriture par le portail
    (cf. §3.4) : une ligne partielle serait ignorée (`JSONDecodeError`) puis
    relue complète au tour suivant (nouvelle clé `_seen`) → **auto-correcteur**,
    plutôt robuste en pratique.
- **Sécurité** : la victime ne lit que des URL construites à partir de
  `dest_ip`/`port` issus de jobs contrôlés. Pas d'injection de commande, pas
  d'`eval`. Le seul « danger » (CERT_NONE) est le sujet du TP.

---

## 6. `targets/scapy-warmup/beacon.py` — la cible balise (C2)

- **L35–48** `_beacon_loop` : émet toutes les 5 s un paquet **broadcast L2**
  (`Ether(ff:ff…)/IP(255.255.255.255)/UDP/Raw`) portant la consigne. `except`
  large annoté « lab ». Bien pour la robustesse.
- **L51–66** `_on_magic` : ne répond que si (a) UDP+Raw présents, (b) `dport ==
  PORT`, (c) payload commence par `MAGIC`. **Bon filtrage défensif** avant de
  répondre. La réponse contient `flag=<FLAG>` renvoyée à l'émetteur. Points de
  revue :
  - Le flag est renvoyé à **quiconque** émet le paquet magique sur le réseau
    isolé — c'est le principe (l'étudiant doit forger le bon paquet). Confiné au
    segment L2 du lab.
  - **L26** `FLAG` lu depuis l'environnement → rotation possible. Bien.
- **L69–73** `main` : lance la balise dans un **thread daemon** puis `sniff`
  bloquant filtré `udp port 8452`. Le filtre BPF réduit la charge. Correct.
- **Sécurité / privilège** : Scapy en L2 exige `NET_RAW/NET_ADMIN` — accordés
  **au conteneur** (compose), pas à l'étudiant sur l'hôte. Le Dockerfile le
  rappelle. La revue vérifie que ce conteneur n'a **que** ces capacités
  (pas de `privileged: true`) — confirmé côté compose.

---

## 7. `solutions/scapy/*.py` — corrigés offensifs

Code de référence de l'enseignant. La revue vérifie **exactitude** et **sobriété**,
et surtout que ces scripts **ne sont pas embarqués** dans les images étudiantes
(ils sont sous `solutions/`, synchronisés seulement sur le serveur prof en mode 3
— cf. revue Ansible §5.1).

- **`arp_spoof.py`** : empoisonnement ARP bidirectionnel (RFC 826). Points forts
  de revue : (a) le docstring **rappelle d'activer `ip_forward`** sous peine de
  DoS au lieu d'interception — pédagogiquement honnête ; (b) `restore()` rétablit
  les tables ARP à l'arrêt (5 rafales) → **nettoyage propre**, réflexe
  professionnel ; (c) `_mac()` gère l'absence de réponse (exit 1). Correct et
  sobre.
- **`sniff_http_flag.py`** : sniff TCP + regex `FLAG\{[^}]+\}`, dédoublonnage par
  ensemble. Minimal, correct. La regex est bornée (`[^}]+`) → pas de catastrophic
  backtracking.
- **`scapy_warmup_solve.py`** : enchaîne écoute de balise, forge, `sr1`, extraction
  par regex. `--iface` optionnel, `argparse` propre, codes de sortie corrects.
- **Points de revue communs** : shebang + `# type: ignore` sur l'import Scapy
  (dépendance sans stubs) — acceptable. Tous requièrent root (raw sockets) : à
  documenter. Aucune écriture hors stdout, aucun effet de bord persistant hormis
  l'ARP (restauré). RAS de sécurité côté corrigés.

---

## 8. Check-list de revue (synthèse actionnable)

Validation des entrées : `dest_ip` **validée** (allow-list privée + `is_private`)
→ **excellent** (anti-SSRF) ; jobs victime **non validés** au niveau des clés
(risque `KeyError` sur job incomplet) → durcir `_replay`.

Secrets & crypto : vérification **à temps constant sur empreinte**
(`hmac.compare_digest`) → **exemplaire** ; RSA-OAEP-2048 correct ; clé privée non
chiffrée et servie **volontairement** (C5) → défaut *pédagogique* confiné, à
cantonner au déploiement isolé ; `flag_digest` = SHA-256 salé fixe → acceptable
car les flags ne sont pas des secrets à protéger.

Robustesse : `except Exception` larges **annotés « lab »** → assumés ; file
d'armement **sans verrou** (concurrence 2 workers) → risque théorique, ajouter
`flock` si l'on durcit ; `_seen` et fichier de file **non purgés** → croissance
lente, négligeable en TP.

Exposition : `app.run(0.0.0.0)` réservé au dev, **gunicorn** en prod (bien) ; le
portail ne doit **jamais** être publié directement côté étudiant (sinon flags
`tls`/`cleartext` lisibles sans attaque) → contrainte de déploiement à documenter.

Séparation of concerns : modèle (`challenges.py`) / service (`app.py`) / acteurs
(`client.py`, `beacon.py`) / corrigés (`solutions/`) bien cloisonnés ; corrigés
**hors images** étudiantes → à garantir en continu.

Intentionnel vs collatéral : les seules « failles » du code (CERT_NONE, clé
servie, flag résident) sont **documentées, bornées et nécessaires** au scénario.
Aucun défaut collatéral non maîtrisé détecté.

---

## 9. Recommandations d'amélioration (durcissement, hors périmètre TP)

1. Valider les clés attendues d'un job dans `_replay` (ou élargir le `try`) pour
   qu'un job incomplet ne casse pas la boucle victime.
2. Protéger l'écriture/lecture de la file par `fcntl.flock` (ou une vraie file
   type Redis) si l'on augmente le nombre de workers ou d'étudiants.
3. Ajouter une purge/rotation du `victim_jobs.jsonl` et borner `_seen`.
4. Documenter explicitement dans le README applicatif la contrainte « ne jamais
   exposer le port du portail directement à l'étudiant ».
5. Optionnel : discriminer le contexte TLS permissif de la victime par challenge
   (n'accepter `CERT_NONE` que pour les challenges qui l'exigent) — plus fidèle au
   réel, au prix d'un peu de complexité.

---

## Annexe A — Flashcards (revue Python)

1. **Q :** Quel est l'invariant du modèle de menace du portail ?
   **R :** Le portail n'est jamais troué au sens *applicatif* ; la vulnérabilité
   est portée par la couche de **transport** (front-end TLS/legacy) placée devant.

2. **Q :** Pourquoi `verify` est-il exemplaire côté sécurité ?
   **R :** Il compare des **empreintes SHA-256 à temps constant**
   (`hmac.compare_digest`) — jamais le flag en clair → ni timing attack, ni flag
   en mémoire de comparaison.

3. **Q :** Comment le portail évite-t-il de devenir un lanceur d'attaque (SSRF) ?
   **R :** `_dest_ip_allowed` n'autorise qu'une IP **privée** appartenant à
   `LAB_CIDR` (double condition `in net` **et** `is_private`).

4. **Q :** Pourquoi le flag C11 est-il stocké dans `_MEMORY_SECRET` et jamais
   renvoyé ?
   **R :** Il doit **résider en mémoire** du processus pour être exfiltrable par
   Heartbleed ; le code applicatif ne le sert jamais (bannière anodine).

5. **Q :** Le `except Exception` de `client.py`/`beacon.py` est-il un défaut ?
   **R :** Non ici : il est **assumé et annoté « lab »** (la victime/balise doit
   survivre aux erreurs réseau). En production ce serait à proscrire.

6. **Q :** Quel padding RSA est utilisé pour C5 et pourquoi est-ce le bon choix ?
   **R :** **OAEP** (MGF1-SHA256) : padding asymétrique sûr, résistant à
   Bleichenbacher — contrairement à PKCS#1 v1.5.

7. **Q :** Quel est le risque de concurrence dans la file d'armement ?
   **R :** Deux workers gunicorn écrivent le même `.jsonl` **sans verrou** →
   entrelacement théorique ; négligeable en TP, à corriger par `flock` si durci.

8. **Q :** Quel job pourrait casser la boucle victime et comment l'éviter ?
   **R :** Un job JSON **valide mais incomplet** (clé manquante) → `KeyError` non
   capturé dans `_replay` ; corriger en validant les clés ou en élargissant le
   `try`.

9. **Q :** Pourquoi les flags par défaut en clair dans `challenges.py` ne sont-ils
   pas un problème ?
   **R :** Ce sont des **replis** surchargés par l'environnement en déploiement ;
   les flags ne sont pas des secrets à protéger mais des cibles **à trouver**.

10. **Q :** Que doit garantir la revue au sujet des scripts `solutions/` ?
    **R :** Qu'ils sont **corrects** et surtout **jamais embarqués** dans les
    images accessibles aux étudiants (ils restent côté serveur prof).

## Annexe B — Glossaire des acronymes

| Acronyme | Développé | Explication |
|----------|-----------|-------------|
| **TLS** | *Transport Layer Security* | Protocole de sécurité de transport ; cœur thématique du lab. |
| **RSA** | *Rivest–Shamir–Adleman* | Chiffrement asymétrique ; paire de clés du portail (C5/C6). |
| **OAEP** | *Optimal Asymmetric Encryption Padding* | Padding RSA sûr (résistant à Bleichenbacher), utilisé pour chiffrer le flag C5. |
| **MGF1** | *Mask Generation Function 1* | Fonction de masque d'OAEP, ici basée sur SHA-256. |
| **HMAC** | *Hash-based Message Authentication Code* | Ici via `hmac.compare_digest` : comparaison à temps constant. |
| **SHA** | *Secure Hash Algorithm* | SHA-256 : empreinte de vérification des flags. |
| **SSRF** | *Server-Side Request Forgery* | Abus où un serveur émet des requêtes vers des cibles arbitraires ; prévenu par l'allow-list d'IP. |
| **ARP** | *Address Resolution Protocol* | Résolution IP→MAC (RFC 826) ; empoisonné par le corrigé MITM. |
| **MAC** | *Media Access Control (address)* | Adresse matérielle L2 ; cible de l'empoisonnement ARP. |
| **UDP** | *User Datagram Protocol* | Transport sans connexion ; support de la balise C2. |
| **BPF** | *Berkeley Packet Filter* | Filtre de capture (`udp port 8452`, `tcp port 8453`). |
| **JSONL** | *JSON Lines* | Un objet JSON par ligne ; format de la file d'armement. |
| **PFS** | *Perfect Forward Secrecy* | Confidentialité persistante ; son absence est le sujet de C6. |
| **CVE** | *Common Vulnerabilities and Exposures* | Identifiants des failles rejouées (Logjam, POODLE, BEAST, Heartbleed…). |

---

## Références

[1] R. C. Martin, *Clean Code: A Handbook of Agile Software Craftsmanship*,
    Prentice Hall, 2008 (séparation des responsabilités, lisibilité).
[2] Python Software Foundation, *Python Documentation — `secrets`, `hmac`,
    `ipaddress`, `ssl`*, docs.python.org.
[3] OWASP, *Code Review Guide* & *Input Validation Cheat Sheet*, owasp.org.
[4] OWASP, *Server-Side Request Forgery Prevention Cheat Sheet*, owasp.org.
[5] D. J. Bernstein, *Cache-timing attacks* ; Python `hmac.compare_digest`
    (comparaison à temps constant).
[6] M. Bellare, P. Rogaway, *Optimal Asymmetric Encryption* (OAEP), EUROCRYPT
    1994 ; PKCS #1 v2.2 (RFC 8017).
[7] ANSSI, *Guide de sélection d'algorithmes cryptographiques* (tailles de clés
    RSA ≥ 2048) ; NIST SP 800-57.
[8] IETF, *RFC 6520 (Heartbeat)*, *RFC 826 (ARP)*, *RFC 5280 (X.509/PKI)*.

---
*Revue de code à usage interne — ANSSI / CFSSI. Les « failles » relevées dans le
code applicatif sont, sauf mention explicite, **intentionnelles, documentées et
confinées** au laboratoire isolé.*
