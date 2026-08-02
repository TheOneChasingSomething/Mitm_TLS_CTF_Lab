# Revue de code — scripts Ansible du TP « Sécurité HTTPS »

> Document de relecture. Objectif : expliquer *comment lire* ces scripts pour en
> conduire une revue, puis détailler chaque fichier ligne à ligne, en séparant ce
> que fait le code de ce qu'un relecteur doit **vérifier** (idempotence, secrets,
> privilèges, portabilité). La revue de sécurité du **mode 3** (comptes système,
> `sudo`, SSH `ForceCommand`) fait l'objet d'une section dédiée.

## 1. Méthode : dans quel ordre lire un dépôt Ansible

Ansible n'a pas de « point d'entrée » unique comme un `main()` : la logique est
distribuée entre configuration, inventaire, variables, *playbooks* et rôles. Une
revue efficace suit donc le **flux des données**, du plus général au plus concret
[1, 2] :

1. **`ansible.cfg`** — les défauts qui conditionnent *tout* le reste (quel
   inventaire, quelle politique SSH, où sont les rôles).
2. **`inventory.ini`** — *sur quoi* on agit : quels hôtes, quels groupes, quelles
   variables de connexion.
3. **`group_vars/all.yml`** — les **variables** qui paramètrent les rôles. C'est
   le fichier le plus important à relire : toute valeur sensible (secrets,
   sous-réseaux, chemins) y naît ou y transite.
4. **`site.yml` / `centralized.yml`** — les *playbooks* : l'**orchestration**
   (quel rôle sur quel groupe, avec quelle élévation de privilèges `become`).
5. **`roles/*/tasks/main.yml`** — les tâches, dans leur ordre d'exécution.
6. **`roles/*/templates/*.j2`** — les **artefacts réellement déployés** (ici, les
   fichiers `docker-compose.yml` rendus). C'est là que se matérialise la surface
   d'exposition (ports, volumes, réseaux, capacités).

Règle de lecture transverse : **tracer une variable** de sa définition à ses
usages. Trois variables méritent ce traçage car elles portent le risque :
`flags` (secrets), `teacher_ip` (cible réseau), `student_instances`
(identités + clés SSH → création de comptes).

Points de contrôle génériques à garder en tête pendant toute la lecture [1, 3] :
idempotence (rejouer le playbook ne doit rien changer), gestion des secrets
(rien en clair), moindre privilège (`become` au plus juste), portabilité
(hypothèses sur la distribution), et *fail-safe* (que se passe-t-il si une tâche
échoue à mi-parcours).

---

## 2. Fichiers d'entrée

### 2.1 `ansible.cfg`

```ini
1  [defaults]
2  inventory = inventory.ini
3  host_key_checking = False
4  retry_files_enabled = False
5  roles_path = roles
6  stdout_callback = yaml
```

- **L2** fixe l'inventaire par défaut : on n'a pas à passer `-i` à chaque appel.
- **L3 — point de vigilance sécurité.** `host_key_checking = False` désactive la
  vérification de l'empreinte SSH des hôtes gérés. C'est commode pour un parc qui
  se recrée souvent (les empreintes changent), mais cela **retire une protection
  contre l'homme-du-milieu** au premier contact [4]. Acceptable sur un réseau de
  TP *physiquement maîtrisé* ; à documenter comme risque résiduel, et à ne pas
  reproduire tel quel en production (préférer un `known_hosts` pré-provisionné).
- **L4** désactive les fichiers `.retry` (propreté).
- **L5** déclare `roles/` comme chemin des rôles (cohérent avec l'arborescence).
- **L6** rend la sortie lisible (YAML), sans impact fonctionnel.

Ce qu'un relecteur note : aucune section `[privilege_escalation]` explicite ; le
`become` est donc décidé play par play (voir §3). Aucun `pipelining`/`ssh_args`
personnalisé → comportement SSH par défaut.

### 2.2 `inventory.ini`

```ini
6  [teacher]
7  prof ansible_host=192.168.50.1
9  [students]
10 poste01 ansible_host=192.168.50.11
...
15 [all:vars]
16 ansible_user=lab
17 ansible_python_interpreter=/usr/bin/python3
```

- Deux groupes structurent toute l'orchestration : `teacher` (un hôte) et
  `students` (N hôtes). **En mode 3, le groupe `students` n'est pas utilisé** :
  les « instances » étudiantes sont des *conteneurs* sur `teacher`, décrits par
  la variable `student_instances` (§2.4), pas des machines de l'inventaire. Ne
  pas confondre les deux notions d'« étudiant » est un point de compréhension clé
  pour la revue.
- **L16** `ansible_user=lab` : compte de connexion Ansible sur les hôtes. Le
  relecteur vérifie que ce compte a bien `sudo` (les plays utilisent `become`).
- **L17** épingle l'interpréteur Python (évite l'auto-découverte, plus stable).
- **À vérifier** : `groups['teacher'][0]` (utilisé en L12 de `group_vars`)
  suppose qu'il existe **au moins un** hôte dans `[teacher]`. Un `[teacher]` vide
  ferait échouer le rendu de `teacher_ip`. Pas de garde explicite → point à
  documenter.

### 2.3 `requirements.yml`

```yaml
3  collections:
4    - name: ansible.posix        # module synchronize (rsync)
5    - name: community.docker     # optionnel : docker_compose_v2 / docker_image
```

- Déclare les **dépendances de collections**. `ansible.posix` est **requis**
  (module `synchronize` et `authorized_key`). `community.docker` est marqué
  optionnel — **incohérence mineure à relever** : le code n'utilise pas ses
  modules (il passe par `command: docker compose …`), donc l'« option » n'est
  jamais exercée. Soit on l'utilise (recommandé, voir §7), soit on retire la
  ligne pour ne pas induire en erreur.
- **À vérifier** : aucune version n'est épinglée. Pour une revue rigoureuse, on
  épinglerait (`version:`) afin de garantir la reproductibilité [1].

### 2.4 `group_vars/all.yml` — le fichier central

Trois blocs. **Bloc salle de TP (L4–21)** :

- `lab_domain`, `lab_subnet` (172.28.0.0/16), `portal_port` (5000),
  `lab_project_dir` (/opt/tls-lab) : paramètres partagés.
- **L12** `teacher_ip` est *dérivé* de l'inventaire :
  `hostvars[groups['teacher'][0]]['ansible_host'] | default(groups['teacher'][0])`.
  Lecture : « l'IP déclarée du premier hôte du groupe `teacher`, à défaut son
  nom d'inventaire ». C'est ce qui permet aux cibles étudiantes de joindre le
  portail. Un relecteur s'assure que `ansible_host` est bien une **IP joignable
  depuis les postes** (et non une IP d'administration séparée).
- **L20** `image_source: "build"` — **choix de performance à challenger.** En
  `build`, *chaque* poste reconstruit les images, dont des cibles lourdes
  (Heartbleed compile OpenSSL 1.0.1f ; Logjam tire `ubuntu:14.04`). Sur un parc,
  `load` (images pré-cuites, `docker save`/`docker load`) est nettement
  préférable. La valeur par défaut mérite un commentaire de revue.

**Bloc secrets (L23–37)** :

- `flags` : les onze drapeaux, **en clair**. Le commentaire L23 recommande déjà
  `ansible-vault` — la revue **confirme cette recommandation comme bloquante**
  pour tout dépôt versionné : des secrets en clair dans Git sont une fuite [1, 5].
  Chiffrer via `ansible-vault encrypt group_vars/all.yml` (ou déplacer les flags
  dans un `vault.yml` chiffré) avant tout commit partagé.
- Le commentaire L24–25 explicite une **invariante fonctionnelle** importante :
  le *même* jeu de flags doit aller au portail **et** aux cibles, sinon les
  empreintes de vérification ne concordent pas. Un relecteur garde cette
  invariante en tête en lisant les templates.

**Bloc mode 3 (L39–54)** :

- `instance_subnet_base: "172.29"` → chaque instance i obtient `172.29.<i>.0/24`.
  **À vérifier** : l'index i vient de `range(1, N+1)` (voir tasks §4). Au-delà de
  **254 étudiants**, le troisième octet déborderait (172.29.255.x puis 172.29.256
  invalide) → limite implicite à documenter. Vérifier aussi l'absence de
  collision avec `lab_subnet` (172.28.x) : OK, plages disjointes.
- `common_c1_flag: "{{ flags.FLAG_C1 }}"` : C1 est **commun** (embarqué dans le
  certificat de l'image partagée). Assumé et documenté ; les autres flags sont
  uniques (voir template §5).
- `student_instances` (L51–54) : **la donnée la plus sensible du dépôt.** Chaque
  entrée `{login, ssh_pubkey}` déclenche la création d'un **compte système** et
  le dépôt d'une **clé SSH autorisée**. Points de revue :
  - `login` sert à nommer un utilisateur (`tp-<login>`), un projet Docker, un
    fichier `sudoers`, un conteneur. Il est donc injecté dans des **noms de
    ressources et des chemins**. Un `login` malformé (espaces, `/`, `..`,
    métacaractères shell) serait un vecteur d'injection → **valider en amont**
    que `login` correspond à `^[a-z0-9_-]+$`. Ce contrôle **n'existe pas** dans le
    code actuel : recommandation de revue (voir §7).
  - `ssh_pubkey` est déployé tel quel : vérifier qu'il s'agit bien de **clés
    publiques** (jamais privées), une par étudiant, sans options parasites.

### 2.5 `site.yml` et `centralized.yml` — orchestration

```yaml
# site.yml
- hosts: teacher   ; become: true ; roles: [common, portal]
- hosts: students  ; become: true ; roles: [common, targets]
```
```yaml
# centralized.yml
- hosts: teacher   ; become: true ; roles: [common, centralized]
```

- Lecture immédiate : **où** s'exécute **quoi**, et **avec quels privilèges**.
- **`become: true` au niveau du play** : *toutes* les tâches des rôles tournent
  en root. C'est nécessaire (installer Docker, créer des utilisateurs, écrire
  dans `/etc/sudoers.d`), mais un relecteur note que le principe de moindre
  privilège voudrait, idéalement, un `become` **au niveau des tâches** qui en ont
  besoin plutôt que globalement [3]. Compromis acceptable ici vu que l'essentiel
  des tâches est privilégié.
- `common` est systématiquement en tête → garantit Docker présent avant tout
  déploiement. Bonne dépendance implicite.
- **Ce que le relecteur vérifie** : les deux playbooks ne doivent pas être joués
  *ensemble* sur le même hôte `teacher` (site.yml *et* centralized.yml y
  déploieraient deux topologies concurrentes sur le port 5000 / le réseau
  172.28). Ce sont des modes **alternatifs** ; à préciser dans la doc d'exploi-
  tation.

---

## 3. Rôle `common` — installation de Docker

```yaml
5  - name: Paquets prérequis (apt: ca-certificates, curl, gnupg, rsync)
11 - name: Clé GPG du dépôt Docker (get_url → /etc/apt/keyrings/docker.asc)
17 - name: Dépôt Docker (apt_repository, signed-by=…)
23 - name: Docker Engine + Compose v2 (apt: docker-ce…, docker-compose-plugin)
29 - name: Service docker actif (service: started, enabled)
35 - name: Répertoire projet (file: state=directory, 0755)
```

Déroulé classique et correct d'installation Docker CE sur Debian/Ubuntu [6].
Points de revue :

- **L11–15 (clé GPG) — supply chain.** La clé est téléchargée par `get_url` sans
  `checksum:`. Un relecteur soucieux de la chaîne d'approvisionnement épinglerait
  une empreinte attendue, ou embarquerait la clé dans le dépôt. Par ailleurs, le
  `dest` écrit dans `/etc/apt/keyrings/` : ce répertoire existe sur Ubuntu récent
  mais **pas garanti** ailleurs → ajouter une tâche `file: path=/etc/apt/keyrings
  state=directory mode=0755` en amont rend le rôle robuste. **Idempotence** :
  `get_url` re-télécharge si le fichier distant change ; acceptable.
- **L17–L19** utilise `{{ ansible_distribution_release }}` (p. ex. `jammy`). Sur
  une **Debian** (et non Ubuntu), l'URL `…/ubuntu` serait incorrecte → le rôle
  est **Ubuntu-centré**. Le commentaire L3 le dit ; la revue confirme que le
  portage RHEL/Debian n'est pas traité.
- **Idempotence globale** : les modules `apt`, `apt_repository`, `service`,
  `file` sont **nativement idempotents** — rejouer le rôle ne change rien. Bon
  point.
- **Sécurité** : aucune tâche n'ajoute `ansible_user` au groupe `docker` (ce qui
  équivaudrait à un root sans mot de passe). C'est **volontaire et sain** : les
  commandes Docker passent par `become`/root, pas par appartenance au groupe.

---

## 4. Rôle `portal` et rôle `targets` (mode salle de TP)

Structure identique et symétrique (à lire ensemble) :

```yaml
# portal                                  # targets
synchronize app/ (si build)               synchronize targets/,victim-client/,scripts/ (si build)
docker load tls-lab-portal.tar (si load)  docker load tls-lab-c*.tar (si load)
template → docker-compose.yml (teacher)   template → docker-compose.yml (student)
docker compose build (si build)           docker compose build (si build)
docker compose up -d                      docker compose up -d
debug: URL d'accès                         debug: rappel
```

Points de revue communs :

- **`synchronize` (rsync).** Efficace pour pousser les contextes de build. Trois
  vérifications : (a) `rsync` doit être présent **des deux côtés** (fourni par
  `common`, OK) ; (b) sous `become: true`, `synchronize` se comporte parfois mal
  (il se connecte comme `ansible_user` puis élève) — à tester réellement, c'est
  un piège récurrent du module [7] ; (c) `delete: true` **efface** côté
  destination ce qui n'est plus côté source → comportement voulu (miroir), mais à
  connaître.
- **`command: docker compose …` — non-idempotence.** Les tâches `build` et
  `up -d` passent par le module `command`. Elles seront **toujours rapportées
  “changed”** et ne portent pas de `changed_when:`/`creates:`. Conséquence : le
  playbook n'est pas proprement idempotent et un `--check` (dry-run) est
  inopérant sur ces tâches. **Recommandation** (voir §7) : utiliser
  `community.docker.docker_compose_v2` (déjà en dépendance) qui, lui, calcule
  l'état. Point de revue important côté qualité.
- **`docker load` en mode load (targets)** utilise `shell:` avec une boucle
  `for f in …/tls-lab-c*.tar`. L'usage de `shell` (et non `command`) est ici
  justifié par le *glob* et la boucle. Vérifier que `image_tarball_dir` est bien
  peuplé au préalable (dépendance externe au playbook).
- **Ordre des tâches** : template *avant* `up -d` (le compose doit exister),
  build *avant* up. Séquencement correct.

### 4.1 Template `docker-compose.teacher.yml.j2`

Un seul service `portal` :

- **L6–10** bascule `build ./app` vs `image: tls-lab-portal` selon
  `image_source`. Le `{% if %}` produit un YAML valide dans les deux cas (vérifié
  par rendu). Bon usage de Jinja.
- **L14–16** injecte les onze flags depuis `flags` → cohérent avec l'invariante
  « mêmes flags portail+cibles ».
- **L17** publie `"{{ portal_port }}:5000"` : **seul port exposé** de tout le
  dispositif salle. Surface d'attaque minimale côté prof.
- **L19** monte `labdata:/data` (paire RSA de C5). Le relecteur relie cela à la
  route `/.well-known/backup/` servie par le portail (fuite volontaire C5).
- **L21 / L26–31** IP statique `172.28.0.10` sur un bridge `lab` en `172.28.0.0
  /16`. Cohérent avec le template étudiant (portail = .10).

### 4.2 Template `docker-compose.student.yml.j2`

- **L5–17** : une **liste `svc`** décrit chaque cible (nom, contexte, IP, ports,
  env/args de flag, `host:` = faut-il ajouter `extra_hosts`). Excellente
  factorisation : la boucle Jinja (L40+) évite 11 blocs dupliqués. La revue vérifie
  la cohérence de cette table (ports, IP .21–.31 sans collision, flags au bon
  endroit).
- **L26–36** : la victime en `VICTIM_MODE=standalone` rejoue une liste **statique**
  de cibles locales (pas d'armement central inter-machines). Le relecteur note
  que `ssl-strip` est ciblé sur `8443` (comportement hérité du mode local ;
  cohérent).
- **`host:true`** ajoute `extra_hosts: ["portal:{{ teacher_ip }}"]` sur les cibles
  qui proxifient vers le portail ; **`host:false`** pour C2 (balise Scapy) et C11
  (Heartbleed, autonome). Vérifier que **toutes** les cibles proxifiantes ont
  bien `host:true` (revue de complétude).
- **C5 (L10)** monte `nginx.classroom.conf` en surcharge → la cible proxifie le
  chemin de fuite vers le portail (la clé n'est pas sur le poste). Point subtil à
  valider : le fichier existe bien dans le contexte synchronisé.
- **Sécurité** : les cibles publient leurs ports **sur le poste étudiant** (8441–
  8453). C'est voulu (l'étudiant attaque en local) mais implique que **le poste
  est root-équivalent sur ses propres cibles** → c'est précisément la faiblesse
  anti-triche que le mode 3 corrige.

---

## 5. Rôle `centralized` (mode 3) — la partie sensible

C'est le cœur de la revue de sécurité. Le rôle fait trois choses (commentaire
L2–5) : construire les images **une fois**, créer **une instance isolée par
étudiant**, puis **confiner l'accès SSH**.

### 5.1 Construction partagée (tasks L7–33)

- **L7–13** `synchronize` de `app, victim-client, targets, attacker, solutions`.
  **Point de revue** : `solutions/` contient le **corrigé** ; il est synchronisé
  sur le serveur prof (acceptable, serveur maîtrisé) mais **ne doit jamais** se
  retrouver dans une image accessible à l'étudiant. Vérifier qu'aucun `Dockerfile`
  n'embarque `solutions/` (l'image `attacker` ne le fait pas). À tracer.
- **L15–33** boucle de `docker build -t tls-lab-<tag>`. **Non-idempotent**
  (`command`), reconstruit à chaque run. L'interpolation
  `{{ item.args | default('') }}` insère `--build-arg FLAG_C1=…` **uniquement**
  pour openssl-warmup. **Vigilance injection** : `command` découpe l'argument sur
  les espaces ; un flag contenant une espace casserait la commande. Les flags
  actuels n'en contiennent pas, mais un contrôle (pas d'espace dans les flags)
  fiabiliserait. Les images sont taguées `tls-lab-*` et **réutilisées** par
  toutes les instances (gain majeur : on ne compile qu'une fois).

### 5.2 Instances isolées (tasks L35–59)

- **L35–41** crée `instances/<login>/` en `0750`.
- **L43–52** rend un `docker-compose.yml` **par étudiant** via un `zip` de
  `student_instances` avec `range(1, N+1)` → fournit `login` et `idx` au template.
  Le relecteur vérifie que `idx` sert bien à l'allocation `/24` (unicité réseau).
- **L54–59** `docker compose -p tp-<login> up -d` : un **projet Docker distinct**
  par étudiant (préfixe `-p`) → isolation des noms de ressources.

### 5.3 Template `docker-compose.instance.yml.j2` — isolation et flags uniques

- **L5–13 — flags uniques.** Boucle Jinja : C1 = `common_c1_flag` (partagé, baké
  cert) ; C2..C11 = `FLAG{cN_<sha1(login::N)[:12]>}`. **Propriété anti-triche
  centrale** : un flag divulgué ne valide chez personne d'autre. Le relecteur
  note que le condensat n'est **pas secret** (dérivable si l'on connaît le login
  et l'algo) — mais l'étudiant n'a **jamais accès** au login-espace ni au portail
  d'un camarade, donc la propriété tient par **isolation**, pas par secret du
  hachage. Bien voir que la sécurité repose sur le cloisonnement réseau + SSH, pas
  sur le hachage.
- **L14–49** portail + victime + **attaquant** par instance, IP `.10/.11/.12`.
  `container_name: tp-<login>-attacker` (L46) est **exactement** la cible du
  `ForceCommand` et de la règle `sudo` → cohérence de nommage à vérifier (elle
  est correcte).
- **L47** l'attaquant reçoit `NET_RAW, NET_ADMIN` (ARP spoofing/sniff). Confiné au
  réseau d'instance.
- **L64–83** boucle des 11 cibles (`image: tls-lab-*`, pas de `build:` → images
  partagées ; env de flag pour C2/C7/C9/C10/C11 ; volume `nginx.classroom.conf`
  pour C5 ; `cap_add` pour C2). **Aucun `ports:` publié** → invisible depuis
  l'hôte.
- **L87–93 — l'isolation réseau.** `internal: true` : le bridge n'a **pas de
  passerelle** → aucune sortie vers l'hôte/Internet, aucune route vers les autres
  instances (les bridges Docker sont isolés entre eux par iptables) [8]. C'est le
  pilier technique de l'anti-triche et de l'endiguement. Le relecteur vérifie que
  `internal: true` est bien présent sur **chaque** instance (il l'est, dans le
  template unique).

### 5.4 Confinement SSH (tasks L61–93) — revue de sécurité détaillée

Trois tâches forment le mécanisme anti-triche. À lire ensemble :

**(a) Compte système (L62–68).**
```yaml
user: name=tp-<login>  shell=/usr/sbin/nologin  create_home=true
```
`nologin` empêche tout shell d'ouverture de session classique. L'accès ne pourra
se faire *que* via le `ForceCommand` de la clé (voir c). Idempotent. **À
vérifier** : pas de mot de passe défini → connexion **par clé uniquement** (bon).

**(b) Règle `sudo` (L70–77).**
```yaml
copy: dest=/etc/sudoers.d/tp-<login>  mode=0440  validate="visudo -cf %s"
content: "tp-<login> ALL=(root) NOPASSWD: /usr/bin/docker exec -it tp-<login>-attacker /bin/bash"
```
- **Portée volontairement minuscule** : l'utilisateur ne peut lancer *que* cette
  commande précise, en root, sans mot de passe. Pas de *wildcard* → pas de
  `docker exec` vers un **autre** conteneur, pas de `docker run`, pas de `docker
  inspect`/`cp` (qui exfiltreraient les flags ou la config) [9].
- **`validate: visudo -cf %s`** : le fichier est **vérifié avant** d'être mis en
  place → une erreur de syntaxe ne casse pas `sudo` sur la machine. Excellent
  réflexe.
- **`mode=0440`** conforme à ce qu'attend `sudoers.d`.
- **Points de revue résiduels** :
  - Le chemin `/usr/bin/docker` doit être le **vrai** chemin (sur certaines
    distros c'est `/usr/local/bin`). Une divergence ferait échouer le `sudo` (ou,
    pire, si un `docker` non-privilégié existait ailleurs dans le PATH… mais la
    règle épingle le chemin absolu, donc pas d'ambiguïté). Vérifier le chemin
    réel sur l'hôte cible.
  - `docker exec -it … /bin/bash` donne un **shell root DANS le conteneur
    attaquant**. Comme ce conteneur porte `NET_ADMIN/NET_RAW`, l'étudiant y est
    root avec ces capacités. Le confinement repose alors entièrement sur
    l'isolation conteneur↔hôte : **pas de socket Docker monté**, réseau
    `internal`, pas de volume hôte sensible. Le relecteur confirme ces trois
    points dans le template (ils sont respectés). Le risque résiduel est une
    **évasion de conteneur** (faille noyau) — recommander `seccomp`/`no-new-
    privileges`/`userns-remap` en durcissement (voir §7).

**(c) Clé SSH confinée (L79–86).**
```yaml
authorized_key: user=tp-<login>  key=<pubkey>  exclusive=true
  key_options: 'command="sudo docker exec -it tp-<login>-attacker /bin/bash",
                no-port-forwarding,no-X11-forwarding,no-agent-forwarding'
```
- **`command="…"` (ForceCommand par clé)** : quelle que soit la commande demandée
  par le client, c'est **cette** commande qui s'exécute [10]. L'étudiant atterrit
  dans son conteneur, point.
- **`no-port-forwarding`** : empêche `ssh -L/-R` → **pas de tunnel** vers l'hôte,
  les autres instances, ou l'extérieur. Combiné au réseau `internal`, ferme la
  voie d'exfiltration hors-bande. `no-X11/-agent-forwarding` : durcissement
  complémentaire.
- **`exclusive=true`** : purge toute autre clé de cet utilisateur → l'étudiant ne
  peut pas se re-provisionner un autre accès. Bien.
- **Point de revue important (cohérence PTY).** `docker exec -it` exige un TTY ;
  la clé **n'a pas** `no-pty` (retiré à dessein), donc l'étudiant doit se
  connecter avec `ssh -t`. Le relecteur vérifie que la doc étudiante indique bien
  `ssh -t` (elle le fait). Envisager un `command` qui force le TTY côté serveur
  pour éviter la dépendance au flag client.
- **Chaînage sudo↔clé** : le `ForceCommand` appelle `sudo docker exec …`, et la
  règle `sudoers` autorise **exactement** cette commande. Les deux doivent rester
  **rigoureusement identiques** (même login, même nom de conteneur, même chemin).
  Toute divergence (ex. renommage du conteneur) casse l'accès. C'est le principal
  **couplage fragile** du dispositif : à signaler en revue.

**Synthèse de la chaîne de confinement** (défense en profondeur) : `nologin`
(pas de shell hôte) → clé avec `ForceCommand` (pas de commande libre) →
`no-port-forwarding` (pas de tunnel) → `sudo` à périmètre unitaire (pas de Docker
arbitraire) → conteneur sans socket Docker → réseau `internal` (pas d'egress ni
de latéralité) → flags uniques (pas de partage). Chaque maillon est nécessaire ;
la revue vérifie qu'aucun n'est affaibli indépendamment.

---

## 6. Check-list de revue (synthèse actionnable)

Idempotence : modules natifs (apt, file, user, copy, authorized_key,
apt_repository, service) → **OK** ; tâches `command/shell: docker …` →
**non-idempotentes** (à migrer vers `community.docker`).

Secrets : `flags` en clair dans `group_vars` → **chiffrer (ansible-vault)** avant
tout versionnement partagé ; ne jamais committer de clé **privée** dans
`student_instances`.

Moindre privilège : `become` au niveau *play* (large mais justifié) ; `sudoers`
mode 3 à périmètre **unitaire** (excellent) ; pas d'ajout au groupe `docker`
(bon).

Validation des entrées : **`login` non validé** → ajouter un contrôle
`^[a-z0-9_-]+$` (injection dans noms de ressources/chemins/sudoers) ; s'assurer
que `ssh_pubkey` est une clé **publique**.

Portabilité : rôle `common` **Ubuntu-centré** (URL du dépôt, `keyrings`) →
documenter/porter pour Debian/RHEL ; créer `/etc/apt/keyrings` explicitement.

Réseau/isolation : `internal: true` présent sur les instances (**pilier**) ;
plages 172.28 (salle) et 172.29.x (instances) disjointes ; limite implicite à
**254 instances**.

Robustesse : `host_key_checking=False` (risque MITM SSH assumé en TP) ; clé GPG
Docker **sans checksum** (chaîne d'approvisionnement) ; couplage **fragile**
nom-de-conteneur ↔ sudoers ↔ ForceCommand (mode 3).

Fail-safe : `validate: visudo` protège `sudo` ; les playcs sont ré-exécutables,
mais une coupure en plein `docker build` laisse un état partiel (pas de
transaction) → relancer est sûr (idempotence des étapes de provisioning).

---

## 7. Recommandations d'amélioration (hors périmètre du TP, pour durcir)

1. Remplacer `command: docker compose …` par `community.docker.docker_compose_v2`
   (idempotence + `--check`), déjà en dépendance.
2. Chiffrer les flags avec `ansible-vault` ; sortir les secrets de
   `group_vars/all.yml` vers un `vault.yml`.
3. Valider `login` (`assert` avec regex) en tête du rôle `centralized`.
4. Créer `/etc/apt/keyrings` explicitement et ajouter un `checksum:` à la clé GPG.
5. Durcir le conteneur attaquant : `security_opt: [no-new-privileges:true]`,
   profil `seccomp`, `userns-remap` côté démon, et ne garder que `NET_RAW/
   NET_ADMIN` (déjà le cas) — pour contenir une éventuelle évasion.
6. Épingler les versions de collections dans `requirements.yml`.
7. Ajouter un garde-fou si `[teacher]` est vide, et documenter que `site.yml` et
   `centralized.yml` sont **mutuellement exclusifs** sur un même hôte.

---

## Annexe A — Flashcards (revue de code Ansible)

1. **Q :** Dans quel ordre lit-on un dépôt Ansible pour une revue ?
   **R :** `ansible.cfg` → inventaire → `group_vars` → *playbooks* (plays,
   `become`) → `roles/*/tasks` → templates `.j2` ; puis on **trace les variables
   sensibles** (secrets, IP cible, identités).

2. **Q :** Pourquoi les tâches `command: docker compose …` posent-elles un
   problème de revue ?
   **R :** Le module `command` n'évalue pas l'état → tâches **non idempotentes**,
   toujours “changed”, et `--check` inopérant. Préférer
   `community.docker.docker_compose_v2`.

3. **Q :** Où naissent les secrets dans ce dépôt et que faut-il en faire ?
   **R :** Les `flags` dans `group_vars/all.yml`, **en clair** → les chiffrer avec
   `ansible-vault` avant tout versionnement.

4. **Q :** Quels trois mécanismes forment le confinement SSH du mode 3 ?
   **R :** Compte `nologin`, clé SSH avec `command="…"` + `no-port-forwarding`, et
   règle `sudoers` à **périmètre unitaire** (`docker exec -it` du seul conteneur
   de l'étudiant).

5. **Q :** Sur quoi repose *réellement* l'anti-triche : le secret des flags ou
   l'isolation ?
   **R :** L'**isolation** (réseau `internal`, SSH confiné, pas d'accès Docker/
   hôte). Les flags uniques empêchent le partage, mais leur dérivation n'est pas
   secrète.

6. **Q :** Pourquoi `validate: visudo -cf %s` est-il un bon réflexe ?
   **R :** Il **vérifie la syntaxe** du fichier `sudoers` avant de l'installer :
   une erreur ne casse pas `sudo` sur la machine.

7. **Q :** Quel est le couplage fragile du mode 3 ?
   **R :** Le **nom du conteneur** (`tp-<login>-attacker`) doit être identique
   dans le template, la règle `sudoers` et le `ForceCommand` ; toute divergence
   casse l'accès.

8. **Q :** Quel champ ferme l'exfiltration hors-bande par tunnel SSH ?
   **R :** `no-port-forwarding` dans `key_options`, combiné au réseau Docker
   `internal: true`.

9. **Q :** Pourquoi `internal: true` est-il central ?
   **R :** Le bridge n'a pas de passerelle → aucune sortie ni route vers les
   autres instances ; c'est l'endiguement réseau de chaque étudiant.

10. **Q :** Quelle entrée utilisateur devrait être validée et pourquoi ?
    **R :** `login` : il est injecté dans des noms d'utilisateur, de conteneur, de
    fichier `sudoers` et des chemins → risque d'injection ; imposer `^[a-z0-9_-]+$`.

## Annexe B — Glossaire des acronymes

| Acronyme | Développé | Explication |
|----------|-----------|-------------|
| **YAML** | *YAML Ain't Markup Language* | Format de sérialisation des playbooks et variables Ansible. |
| **SSH** | *Secure Shell* | Protocole d'accès distant chiffré ; support de `ForceCommand` et des options de clé. |
| **GPG** | *GNU Privacy Guard* | Signature/chiffrement ; ici, clé de vérification du dépôt APT Docker. |
| **APT** | *Advanced Package Tool* | Gestionnaire de paquets Debian/Ubuntu (installation de Docker). |
| **CE** | *Community Edition* | Édition communautaire de Docker Engine. |
| **PTY** | *Pseudo-TeletYpe* | Terminal virtuel requis par `docker exec -it` (d'où `ssh -t`). |
| **MITM** | *Man-In-The-Middle* | Menace visée par `host_key_checking` (vérification d'empreinte SSH). |
| **CIDR** | *Classless Inter-Domain Routing* | Notation des sous-réseaux (`172.29.<i>.0/24`). |
| **IPAM** | *IP Address Management* | Bloc Docker Compose allouant les sous-réseaux/IP statiques. |
| **RSA** | *Rivest–Shamir–Adleman* | Paire de clés du portail (volume `labdata`, fuite C5). |
| **RHEL** | *Red Hat Enterprise Linux* | Famille de distributions non couverte par le rôle `common` (Ubuntu-centré). |
| **DoS** | *Denial of Service* | Risque générique d'un provisioning ou d'une capacité réseau mal cadrés. |
| **PoC** | *Proof of Concept* | (Contexte TP) démonstration d'exploitation, hors périmètre de la revue. |

---

## Références

[1] Red Hat/Ansible, *Ansible Best Practices — Content Organization & Playbook
    Reuse*, docs.ansible.com.
[2] Red Hat/Ansible, *Variable precedence: Where should I put a variable?*,
    docs.ansible.com.
[3] Red Hat/Ansible, *Understanding privilege escalation (become)*,
    docs.ansible.com.
[4] OpenSSH, *ssh_config(5) — StrictHostKeyChecking* ; Ansible,
    *`host_key_checking`*, docs.ansible.com.
[5] Red Hat/Ansible, *Encrypting content with Ansible Vault*, docs.ansible.com.
[6] Docker, *Install Docker Engine on Ubuntu*, docs.docker.com.
[7] Red Hat/Ansible, *`ansible.posix.synchronize` module — Notes (become &
    rsync)*, docs.ansible.com.
[8] Docker, *Networking overview — bridge driver & `internal` networks*,
    docs.docker.com.
[9] T. Miller *et al.*, *sudoers(5) — Command specifications & security policy*,
    OpenBSD/Sudo project.
[10] OpenSSH, *sshd(8) — AUTHORIZED_KEYS FILE FORMAT (`command`, `no-port-
    forwarding`)*.
[11] Center for Internet Security, *CIS Docker Benchmark* (durcissement
     conteneurs : `no-new-privileges`, capacités, userns).

---
*Revue de code à usage interne — ANSSI / CFSSI. Les points marqués « recommandation »
sont des durcissements optionnels, sans impact sur le fonctionnement du TP.*
