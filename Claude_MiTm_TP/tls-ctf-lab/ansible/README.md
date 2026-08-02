# Classroom deployment (Ansible)

> 🇬🇧 English below · 🇫🇷 Version française plus bas.

This directory deploys the lab across a **fleet of machines**:

- **one "teacher" machine** hosts the **portal** — the site that *receives* the
  flag feeds (proxied by the targets) and *verifies* submissions. It is the
  centralization point (dashboard + grading);
- **each student workstation** hosts the **vulnerable targets** and the
  **victim-client** (*standalone* mode). The targets proxy to the central
  portal: the hostname `portal` is resolved to the teacher's IP via
  `extra_hosts`.

This is the second of the lab's deployment modes:

| Mode | Tool | Topology | File |
|------|------|----------|------|
| **Local** (single host) | Packer + Compose | everything on one machine (or a `qcow2` VM) | `../docker-compose.yml`, `../packer/` |
| **Classroom** (fleet) | Ansible (+ Packer) | portal on the teacher, targets on the workstations | `site.yml` (below) |
| **Centralized anti-cheat** | Ansible (+ Packer) | everything on the teacher server, one isolated instance per student, SSH access | `centralized.yml` (see further down) |

## Prerequisites

- An Ansible controller with SSH (sudo) access to the machines.
- `ansible-galaxy collection install -r requirements.yml` (provides `synchronize`).
- Debian/Ubuntu target machines (the `common` role installs Docker + Compose v2;
  adapt for RHEL/Rocky).
- The teacher machine must be **reachable** from the workstations on the portal
  port (`5000` by default).

## Getting started

1. **Inventory** — set the real IPs in `inventory.ini`: one `[teacher]` host,
   N `[students]` hosts.
2. **Variables** — adjust `group_vars/all.yml` (portal port, flags, image
   source). Ideally, encrypt the flags with `ansible-vault`.
3. **Deploy**:
   ```sh
   ansible-galaxy collection install -r requirements.yml
   ansible-playbook site.yml
   ```
4. Students open `http://<TEACHER_IP>:5000/` for the dashboard and **flag
   verification**, and attack the **local** targets on their workstation (ports
   8441-8453) — the victim keeps traffic flowing there continuously.

## Image source (`image_source`)

- `build` (default) — each host builds its own images (`docker compose build`).
  Simple, but **slow**: Heartbleed compiles OpenSSL 1.0.1f and Logjam pulls
  `ubuntu:14.04` on *every* workstation.
- `load` — recommended in a classroom: bake the images **once** with Packer,
  export them (`docker save`), distribute the archives, then load them
  (`docker load`). Set `image_tarball_dir`. Export example:
  ```sh
  cd ../packer && packer build -only='docker.*' .
  docker save tls-lab-portal -o images/tls-lab-portal.tar
  # … same for each tls-lab-cX target
  ```

## Victim arming model (important)

In local mode, the portal arms the victim via a shared volume (*Start* button →
job queue). **In a classroom, portal and victim run on different machines**: that
volume coupling is impossible. The victim therefore switches to **standalone**
mode (`VICTIM_MODE=standalone`): it replays, in a loop, a static list of **local**
targets (`VICTIM_STANDALONE_TARGETS`), so that interceptable traffic flows
permanently, without central arming. The student attacks directly, without the
*Start* button.

## Notes

- **Challenge C5 (key leak)**: the private key to recover is the portal's
  (teacher machine). The student's `key-leak` target therefore proxies the path
  `/.well-known/backup/server.key` to the portal, which exposes it (dedicated
  route). Functionally identical to local mode.
- **Flag rotation**: in `build` mode, all flags are overridden via `group_vars`.
  In `load` mode, runtime-injected flags (cookies C7/C9/C10/C11, beacon C2) and
  portal-served flags (C3/C4/C5/C6/C8) rotate normally; however **FLAG_C1 is
  frozen in the certificate** at image-bake time — rotating it requires rebaking
  the `openssl-warmup` image.
- **Isolation**: each workstation's `lab` network stays an isolated Docker
  bridge; only the portal port crosses the physical network to the teacher. Do
  not route this segment to the Internet (deliberately vulnerable targets).

---

# Mode 3 — Centralized instances (anti-cheat)

A third mode hardens the previous one against cheating. The problem: in a
"classic" classroom (mode 2), the student is **root/docker on their own
workstation** — they can inspect the target images and extract the flags without
performing a single attack. Mode 3 removes that access.

## Principle

**Everything runs on the teacher server**, as **one isolated instance per
student**:

- each instance = its own portal + its targets + **its own victim** + an
  **attacker** container, on a **dedicated, `internal` /24 network** (no egress,
  no route to the other instances);
- **no target port is published** on the host: the targets are reachable only
  from the attacker container of the same instance;
- the student accesses THEIR attacker **through SSH only** (`ForceCommand`), with
  no host shell, no Docker socket, no port-forwarding: they can neither inspect
  the images nor reach the other students' instances;
- the **C2..C11 flags are unique per student** (derived from the login) → a
  leaked flag validates for no one else. (C1 stays common: it is baked into a
  shared image's certificate; rotating it per student would require rebaking the
  `openssl-warmup` image per instance.)

```
  Teacher server
  ├─ shared images (built once)
  ├─ instance tp-etu01  [network 172.29.1.0/24, internal]
  │    portal · victim · c1..c11 · attacker(172.29.1.12)
  │        ▲ SSH ForceCommand
  │   etu01 ──ssh -t tp-etu01@teacher──► /bin/bash in tp-etu01-attacker
  ├─ instance tp-etu02  [network 172.29.2.0/24, internal]  …
  └─ …
```

## Getting started

1. Set `student_instances` in `group_vars/all.yml`: a `login` + an `ssh_pubkey`
   per student (order fixes the index → subnet
   `{{ instance_subnet_base }}.<i>.0/24`).
2. Deploy:
   ```sh
   ansible-galaxy collection install -r requirements.yml
   ansible-playbook centralized.yml           # or: make centralized-instances
   ```
3. Each student connects:
   ```sh
   ssh -t tp-<login>@<TEACHER_IP>
   # → shell in THEIR attacker container, on THEIR isolated network.
   # Targets/victim resolved by name: c3-mitm-http, victim-client, portal…
   ```
   They attack from this foothold (scapy, tcpdump, tshark, nmap, arpspoof,
   openssl…) and verify their flags on `http://portal:5000/` (internal to the
   instance).

## Anti-cheat properties

| Cheating vector | Neutralization |
|-----------------|----------------|
| Read the flag from the target image | The student has no Docker/host access (confined SSH, sudo limited to the single `docker exec` of their attacker). |
| `docker inspect` / container logs | Same: no access to the Docker daemon. |
| Grab a classmate's flag | C2..C11 flags **unique per student**. |
| Attack / sniff another's instance | Distinct, `internal` `/24` networks; Docker bridge isolation. |
| Tunnel to the host or the outside | `no-port-forwarding` in the key + `internal` network. |

## Design choices (assumed)

- **MITM position.** A plain `ssh -L` (L4 forward) would not provide the
  *on-path* position the interception challenges require. The student therefore
  operates from an **attacker container on their victim's network** — they can
  ARP-poison and sniff, but stay confined.
- **One portal per instance.** Simplicity and maximum isolation (unique flags,
  RSA volume specific to C5). For a central dashboard, forward each portal's
  validations to a collector (extension not provided).
- **Not tested in the preparation environment** (no network/Docker): validate the
  playbook on the target server. `ansible-playbook centralized.yml --check`, then
  `--syntax-check` on a first pass.


<br>

---

# 🇫🇷 Version française

# Déploiement « salle de TP » (Ansible)

Ce répertoire déploie le laboratoire sur un **parc de machines** :

- **une machine « prof »** héberge le **portail** — le site qui *reçoit* les flux
  de flags (proxifiés par les cibles) et *vérifie* les soumissions. C'est le
  point de centralisation (tableau de bord + notation) ;
- **chaque poste étudiant** héberge les **cibles vulnérables** et le
  **client-victime** (mode *standalone*). Les cibles proxifient vers le portail
  central : le nom d'hôte `portal` est résolu vers l'IP de la prof via
  `extra_hosts`.

C'est le second des deux modes de déploiement du TP :

| Mode | Outil | Topologie | Fichier |
|------|-------|-----------|---------|
| **Local** (poste unique) | Packer + Compose | tout sur une machine (ou une VM `qcow2`) | `../docker-compose.yml`, `../packer/` |
| **Salle de TP** (parc) | Ansible (+ Packer) | portail sur la prof, cibles sur les postes | `site.yml` (ci-dessous) |
| **Centralisé anti-triche** | Ansible (+ Packer) | tout sur le serveur prof, une instance isolée/étudiant, accès SSH | `centralized.yml` (voir plus bas) |

## Prérequis

- Contrôleur Ansible avec accès SSH (sudo) aux machines.
- `ansible-galaxy collection install -r requirements.yml` (fournit `synchronize`).
- Machines cibles Debian/Ubuntu (le rôle `common` installe Docker + Compose v2 ;
  adapter pour RHEL/Rocky).
- La machine prof doit être **joignable** depuis les postes sur le port du
  portail (`5000` par défaut).

## Mise en œuvre

1. **Inventaire** — renseignez les IP réelles dans `inventory.ini` : un hôte
   `[teacher]`, N hôtes `[students]`.
2. **Variables** — ajustez `group_vars/all.yml` (port du portail, flags,
   provenance des images). Idéalement, chiffrez les flags avec `ansible-vault`.
3. **Déploiement** :
   ```sh
   ansible-galaxy collection install -r requirements.yml
   ansible-playbook site.yml
   ```
4. Les étudiants ouvrent `http://<IP_PROF>:5000/` pour le tableau de bord et la
   **vérification des flags**, et attaquent les cibles **locales** de leur poste
   (ports 8441-8453) — la victime y fait circuler du trafic en permanence.

## Provenance des images (`image_source`)

- `build` (défaut) — chaque hôte construit ses images (`docker compose build`).
  Simple, mais **lent** : Heartbleed compile OpenSSL 1.0.1f et Logjam tire
  `ubuntu:14.04` sur *chaque* poste.
- `load` — recommandé en salle : cuisez les images **une seule fois** avec
  Packer, exportez-les (`docker save`), distribuez les archives puis chargez-les
  (`docker load`). Renseignez `image_tarball_dir`. Exemple d'export :
  ```sh
  cd ../packer && packer build -only='docker.*' .
  docker save tls-lab-portal -o images/tls-lab-portal.tar
  # … idem pour chaque cible tls-lab-cX
  ```

## Modèle d'armement de la victime (important)

En mode local, le portail arme la victime via un volume partagé (bouton
*Démarrer* → file de jobs). **En salle, portail et victime sont sur des machines
différentes** : ce couplage par volume est impossible. La victime passe donc en
mode **standalone** (`VICTIM_MODE=standalone`) : elle rejoue en boucle une liste
statique de cibles **locales** (`VICTIM_STANDALONE_TARGETS`), de sorte qu'un flux
à intercepter circule en permanence, sans armement central. L'étudiant attaque
directement, sans passer par le bouton *Démarrer*.

## Notes

- **Challenge C5 (fuite de clé)** : la clé privée à récupérer est celle du
  portail (machine prof). La cible `key-leak` du poste étudiant proxifie donc le
  chemin `/.well-known/backup/server.key` vers le portail, qui l'expose (route
  dédiée). Fonctionnellement identique au mode local.
- **Rotation des flags** : en mode `build`, tous les flags se surchargent via
  `group_vars`. En mode `load`, les flags injectés à l'exécution (cookies C7/C9/
  C10/C11, balise C2) et les flags servis par le portail (C3/C4/C5/C6/C8) se
  rotent normalement ; en revanche **FLAG_C1 est figé dans le certificat** au
  moment de la cuisson de l'image — le roter impose de recuire l'image
  `openssl-warmup`.
- **Isolement** : le réseau `lab` de chaque poste reste un bridge Docker isolé ;
  seul le port du portail traverse le réseau physique vers la prof. Ne pas router
  ce segment vers Internet (cibles volontairement vulnérables).

---

# Mode 3 — instances centralisées (anti-triche)

Un troisième mode durcit le précédent contre la triche. Le constat : en salle
« classique » (mode 2), l'étudiant est **root/docker sur son poste** — il peut
inspecter les images des cibles et en extraire les flags sans mener la moindre
attaque. Le mode 3 supprime cet accès.

## Principe

**Tout tourne sur le serveur prof**, en **une instance isolée par étudiant** :

- chaque instance = son propre portail + ses cibles + **sa propre victime** +
  un conteneur **attaquant**, sur un **réseau /24 dédié et `internal`** (aucun
  egress, aucune route vers les autres instances) ;
- **aucun port cible n'est publié** sur l'hôte : les cibles ne sont joignables
  que depuis le conteneur attaquant de la même instance ;
- l'étudiant accède à SON attaquant **uniquement par SSH** (`ForceCommand`), sans
  shell hôte, sans socket Docker, sans port-forwarding : il ne peut ni inspecter
  les images, ni atteindre les instances des autres ;
- les **flags C2..C11 sont uniques par étudiant** (dérivés du login) → un flag
  divulgué ne valide chez personne d'autre. (C1 reste commun : il est embarqué
  dans un certificat d'image partagée ; le roter par étudiant imposerait de
  recuire l'image `openssl-warmup` par instance.)

```
  Serveur prof
  ├─ images partagées (construites une seule fois)
  ├─ instance tp-etu01  [réseau 172.29.1.0/24, internal]
  │    portal · victim · c1..c11 · attacker(172.29.1.12)
  │        ▲ SSH ForceCommand
  │   etu01 ──ssh -t tp-etu01@prof──► /bin/bash dans tp-etu01-attacker
  ├─ instance tp-etu02  [réseau 172.29.2.0/24, internal]  …
  └─ …
```

## Mise en œuvre

1. Renseignez `student_instances` dans `group_vars/all.yml` : un `login` + une
   `ssh_pubkey` par étudiant (l'ordre fixe l'index → sous-réseau
   `{{ instance_subnet_base }}.<i>.0/24`).
2. Déploiement :
   ```sh
   ansible-galaxy collection install -r requirements.yml
   ansible-playbook centralized.yml           # ou : make centralized-instances
   ```
3. Chaque étudiant se connecte :
   ```sh
   ssh -t tp-<login>@<IP_PROF>
   # → shell dans SON conteneur attaquant, sur SON réseau isolé.
   # Cibles/victime résolues par nom : c3-mitm-http, victim-client, portal…
   ```
   Il attaque depuis ce point d'appui (scapy, tcpdump, tshark, nmap, arpspoof,
   openssl…) et vérifie ses flags sur `http://portal:5000/` (interne à l'instance).

## Propriétés anti-triche

| Vecteur de triche | Neutralisation |
|-------------------|----------------|
| Lire le flag dans l'image de la cible | L'étudiant n'a pas d'accès Docker/hôte (SSH confiné, sudo limité au seul `docker exec` de son attaquant). |
| `docker inspect` / logs d'un conteneur | Idem : aucun accès au démon Docker. |
| Récupérer le flag d'un camarade | Flags C2..C11 **uniques par étudiant**. |
| Attaquer / sniffer l'instance d'un autre | Réseaux `/24` distincts et `internal` ; isolation bridge Docker. |
| Tunneler vers l'hôte ou l'extérieur | `no-port-forwarding` dans la clé + réseau `internal`. |

## Choix de conception (assumés)

- **Position MITM.** Un simple `ssh -L` (forward L4) ne donnerait pas la position
  *on-path* qu'exigent les challenges d'interception. L'étudiant opère donc
  depuis un **conteneur attaquant sur le réseau de sa victime** — il peut
  empoisonner l'ARP et sniffer, mais reste confiné.
- **Un portail par instance.** Simplicité et isolation maximale (flags uniques,
  volume RSA propre au C5). Pour un tableau de bord central, faire remonter les
  validations de chaque portail vers un collecteur (extension non fournie).
- **Non testé en environnement de préparation** (sans réseau/Docker) : valider le
  playbook sur le serveur cible. `ansible-playbook centralized.yml --check` puis
  `--syntax-check` en première passe.
