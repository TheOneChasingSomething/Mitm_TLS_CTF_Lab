# Revue de code — fichiers Packer du TP « Sécurité HTTPS »

> Document de relecture. Même esprit que les revues Ansible, Python et Docker.
> Packer produit les **livrables immuables** du lab : une image Docker du portail
> (voie alternative au `docker build`) et surtout une **machine virtuelle qcow2
> autonome** embarquant tout le laboratoire — le format idéal pour une salle, car
> il garantit l'**isolement à l'exécution** (aucune dépendance réseau). La revue
> se concentre donc sur : reproductibilité, intégrité des sources, gestion des
> identifiants d'amorçage, et cohérence avec le reste du dépôt.

## 1. Méthode : comment lire un projet Packer (HCL2)

Depuis Packer 1.7, la configuration est en **HCL2** et se lit dans cet ordre
[1, 2] :

1. **`plugins.pkr.hcl`** (bloc `packer { required_plugins }`) — quelles
   *briques* (builders) sont requises et à quelles versions. Récupérées par
   `packer init`.
2. **`variables.pkr.hcl`** (blocs `variable`) — les paramètres surchargables
   (registry, tag, domaine). Point d'entrée du paramétrage.
3. **Les `source`** — *quoi* construire et *à partir de quoi* : image de base
   (docker) ou image cloud (qemu). C'est là que vivent l'**intégrité** (checksum
   d'ISO) et les **identifiants** d'amorçage.
4. **Les `build`** — la séquence : `provisioner` (file, shell) puis
   `post-processor` (tag, manifest). L'ordre est l'exécution.
5. **Les données d'amorçage** — ici `http/user-data` (cloud-init) : le
   *bootstrap* de la VM. À auditer comme du code sensible (identifiants).

Règle transverse : **suivre l'identifiant et la provenance**. Deux questions
dominent une revue Packer — « d'où vient la base et est-elle authentifiée ? » et
« quels secrets d'amorçage sont créés, et restent-ils dans le livrable ? ».

---

## 2. `plugins.pkr.hcl` — plugins requis

```hcl
3  packer { required_plugins {
5    docker = { source = "github.com/hashicorp/docker" ; version = "~> 1.1" }
9    qemu   = { source = "github.com/hashicorp/qemu"   ; version = "~> 1.1" }
} }
```

- Déclare deux builders officiels HashiCorp. **Contrainte `~> 1.1`** : autorise
  1.1.x et 1.x ultérieurs mineurs (*pessimistic constraint*), donc des mises à
  jour mineures automatiques. **Point de revue reproductibilité** : pour un
  livrable de salle rejouable à l'identique, un relecteur préférerait une version
  **exacte** (`= 1.1.0`) ou au moins figée par un *lockfile*
  (`packer init` génère `.pkr.hcl.lock.hcl` — vérifier qu'il est **versionné**
  dans le dépôt ; s'il ne l'est pas, c'est une recommandation).
- Sources = dépôts officiels → confiance raisonnable. Bien.

---

## 3. `variables.pkr.hcl` — paramétrage

```hcl
2  variable "registry" { default = "tls-lab" ; … }
8  variable "tag"      { default = "latest" ; … }
14 variable "lab_domain" { default = "bank.tp.lan" }
```

- Trois variables typées (`string`) avec défauts et descriptions. Surchargables en
  ligne de commande (`-var`). Propre.
- **Point de revue** : `tag = "latest"` par défaut. **`latest` est un anti-motif**
  pour un livrable versionné [3] : il rend l'image produite non identifiable dans
  le temps (deux builds « latest » diffèrent). Recommander un tag **sémantique/
  daté** (ex. `2025.09`) ou l'empreinte du commit.
- `lab_domain` est déclaré mais **non utilisé** dans les `.pkr.hcl` fournis
  (le domaine est figé dans les Dockerfiles / `gen-certs.sh`). **Incohérence
  mineure à relever** : soit le câbler (le passer en `--build-arg`/provisioner),
  soit le retirer pour ne pas suggérer un paramétrage inexistant.

---

## 4. `portal.pkr.hcl` — image Docker du portail par provisioning

```hcl
10 source "docker" "portal" { image = "python:3.12-slim" ; commit = true
13   changes = ["WORKDIR /srv","USER lab","EXPOSE 5000","ENTRYPOINT […gunicorn…]"] }
21 build { sources = ["source.docker.portal"]
26   provisioner "file"  { source = "../app/" ; destination = "/srv/" }
31   provisioner "shell" { inline = [ pip install -r requirements.txt ;
                                       useradd -r -u 10001 lab || true ;
                                       mkdir -p /data/keys && chown -R lab /srv /data ] }
40   post-processor "docker-tag" { repository = "${var.registry}/portal" ; tags = [var.tag] } }
```

Lecture : Packer démarre un conteneur `python:3.12-slim`, y copie l'app, installe
les dépendances, applique des métadonnées (`changes`), puis **committe** l'image
et l'étiquette. Le commentaire cite l'approche « immuable » (Morris, *Infrastructure
as Code*, 2020).

Points de revue :

- **Cohérence avec `app/Dockerfile`.** Cette voie **duplique** la logique du
  Dockerfile portail (mêmes UID 10001, WORKDIR, ENTRYPOINT gunicorn). **Risque de
  dérive** : deux définitions de la même image peuvent diverger dans le temps
  (ex. un correctif appliqué au Dockerfile mais pas au HCL). Un relecteur
  recommande soit de **dériver** l'un de l'autre, soit d'utiliser le
  post-processor Packer **`docker`/`docker-import` sur le Dockerfile** existant,
  pour une **source unique de vérité**. C'est le point de revue le plus important
  de ce fichier.
- **`USER lab` déclaré dans `changes` (L15)** alors que l'utilisateur `lab` n'est
  créé qu'à l'étape `shell` (L34). L'ordre importe : `changes` s'applique au
  **commit** (après les provisioners) → au runtime l'utilisateur existe. **OK**,
  mais subtil : à vérifier que `useradd … || true` (L34) a bien tourné avant le
  commit (c'est le cas, les provisioners précèdent le commit). Le `|| true` évite
  l'échec si l'utilisateur préexiste — idempotence défensive, bien.
- **`pip install` sans `--no-cache-dir`** ici (contrairement au Dockerfile) →
  image légèrement plus grosse. Mineur, mais **incohérence** avec le Dockerfile à
  aligner.
- **`file` provisioner copie `../app/`** : embarque tout le dossier app (templates,
  static, requirements). Vérifier qu'aucun artefact indésirable (clés générées,
  `__pycache__`, `.env`) ne traîne dans `../app/` au moment du build → ajouter un
  filtrage / `.dockerignore`-équivalent ou nettoyer en amont. Point de revue
  d'hygiène.
- `post-processor docker-tag` local ; le commentaire note qu'un `docker-push`
  vers un registry est à ajouter au besoin. Correct.

---

## 5. `lab-vm.pkr.hcl` — VM qcow2 autonome (livrable de salle)

C'est le **cœur** de la revue : un unique qcow2 remis à chaque étudiant.

### 5.1 Source QEMU (L13–36)

```hcl
14 iso_url      = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
15 iso_checksum = "file:https://cloud-images.ubuntu.com/jammy/current/SHA256SUMS"
16 disk_image = true ; format = "qcow2" ; disk_size = "12G" ; memory = 2048 ; cpus = 2
22 accelerator = "kvm" ; headless = true
26 http_directory = "${path.root}/http"
27 qemuargs = [["-smbios","type=1,serial=ds=nocloud-net;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/"]]
31 ssh_username = "lab" ; ssh_password = "labtp" ; ssh_timeout = "20m"
34 shutdown_command = "echo labtp | sudo -S shutdown -P now"
```

Points de revue :

- **Intégrité de la base — BON POINT (L15).** `iso_checksum = "file:…/SHA256SUMS"`
  : Packer récupère la somme officielle et **vérifie** l'image cloud téléchargée.
  Contraste heureux avec les téléchargements sans checksum vus ailleurs (OpenSSL
  C11, GPG Docker). *Nuance* : la somme est récupérée **sur le même serveur** que
  l'image (TOFU) ; pour une chaîne de confiance forte, on ajouterait la
  **vérification GPG** du `SHA256SUMS` (signé par Canonical). Recommandation.
- **`iso_url` = tag `current`** → l'image jammy « courante » évolue dans le temps
  → **reproductibilité** non garantie (deux builds à six mois d'écart partent de
  bases différentes). Recommander d'épingler une **version datée** de l'image
  cloud (les URLs versionnées existent) et son checksum.
- **Identifiants d'amorçage en clair (L31–34)** : `ssh_password = "labtp"` et son
  usage dans `shutdown_command`. **Point de revue central.** C'est un mot de passe
  de **build**, mais il faut vérifier **ce qu'il devient dans le livrable** :
  - S'il **persiste** dans la VM distribuée (compte `lab`/`labtp` + sudo NOPASSWD,
    cf. §5.3), alors **toutes les VM de salle partagent un identifiant connu et
    trivial** → acceptable *uniquement* parce que la VM est **hors ligne et
    isolée** ; à **documenter comme risque assumé** et à ne jamais utiliser hors
    salle. Idéalement, une étape de *cleanup* en fin de build **change/expire** ce
    mot de passe ou verrouille le compte.
  - Le mot de passe apparaît **en clair dans le HCL et dans `shutdown_command`**
    → ne pas le committer tel quel dans un dépôt public ; le passer en **variable
    sensible** (`-var`, ou `PKR_VAR_…`) est préférable.
- **Ressources** (12 G disque, 2 Go RAM, 2 vCPU) : correctes pour faire tourner
  ~5–11 conteneurs de TP ; un relecteur peut questionner 2 Go si **toutes** les
  cibles legacy tournent simultanément (Heartbleed compile au build, pas au run,
  donc le run est plus léger). À valider par test de charge.
- **`accelerator = "kvm"`** : impose une machine de build avec KVM → dépendance
  d'environnement à documenter (échec sur hôte sans virtualisation matérielle).
- **cloud-init via SMBIOS (L27)** : mécanisme `nocloud-net` standard, propre.

### 5.2 Build : provisioners (L38–57)

```hcl
43 provisioner "file"  { source = "../.." ; destination = "/home/lab/tls-ctf-lab" }
49 provisioner "shell" { inline = [
     "echo labtp | sudo -S apt-get update",
     "sudo … apt-get install -y docker.io docker-compose-plugin",
     "sudo usermod -aG docker lab",
     "cd /home/lab/tls-ctf-lab && sudo docker compose build",
     "sudo systemctl enable docker" ] }
```

- **L43 `source = "../.."`** : copie **tout le dépôt** dans la VM, y compris
  **`solutions/`** (les corrigés) ! **Point de revue majeur.** Contrairement au
  mode 3 (où seul le serveur prof reçoit `solutions/`), ici la VM est **remise à
  l'étudiant**. Un étudiant peut donc lire `/home/lab/tls-ctf-lab/solutions/…` →
  **fuite des corrigés**. **Recommandation forte** : exclure `solutions/` (et tout
  matériel enseignant) du provisioning de la VM étudiante, ou l'effacer dans une
  étape de cleanup avant le commit du qcow2. C'est le défaut le plus important de
  toute la chaîne Packer.
- **`docker.io` (dépôt Ubuntu) au lieu du dépôt Docker CE** : divergence avec le
  rôle Ansible `common` (qui installe `docker-ce`). Fonctionnel, mais version
  potentiellement plus ancienne ; à assumer/documenter (cohérence des chaînes).
- **`usermod -aG docker lab`** : l'utilisateur `lab` devient membre du groupe
  `docker` → **équivalent root** sans mot de passe. Dans une VM de TP **isolée
  mono-utilisateur**, c'est le compromis d'ergonomie habituel (l'étudiant lance
  les conteneurs) ; mais à **documenter** comme tel — sur la VM, l'étudiant est de
  fait administrateur (ce qui est cohérent avec un livrable « bac à sable
  personnel », à l'opposé du mode 3 anti-triche).
- **`docker compose build` au build de la VM (L54)** : **excellent pour
  l'objectif** — les images sont **pré-construites**, la VM tourne ensuite **hors
  ligne** (isolement garanti, plus de dépendance à openssl.org / Docker Hub /
  dépôts EOL au démarrage). C'est précisément ce que les revues Docker/Ansible
  recommandaient (pré-cuisson). Point fort.
- **Absence d'étape de nettoyage** (caches apt, historique shell, clés SSH host,
  `solutions/`, mot de passe de build) avant le commit → à ajouter (hygiène +
  taille + sécurité).

### 5.3 `http/user-data` — cloud-init d'amorçage

```yaml
users:
  - name: lab
    sudo: ALL=(ALL) NOPASSWD:ALL
    passwd: "$6$rounds=4096$labsalt$…"   # mot de passe : labtp
ssh_pwauth: true
chpasswd: { expire: false }
```

- **`sudo NOPASSWD:ALL` + `ssh_pwauth: true` + mot de passe trivial non expirant**
  : c'est un profil d'amorçage **très permissif**. Justifié pour un **build**
  automatisé, mais **s'il subsiste** dans la VM livrée, la VM est administrable par
  un mot de passe connu et faible avec authentification par mot de passe activée.
  - **En salle isolée** : risque **assumable** (VM hors ligne, usage personnel),
    mais à **documenter explicitement**.
  - **Recommandations** : (a) désactiver `ssh_pwauth` dans le livrable final ;
    (b) expirer/verrouiller ou régénérer le mot de passe en fin de build ; (c) ne
    pas laisser le **hash** dans un fichier versionné public. Le hash est un `$6$`
    (SHA-512-crypt, 4096 tours) — correct **en tant que** hash, mais protège un
    secret trivial connu (« labtp ») donc sa robustesse est illusoire ici.
- `#cloud-config` bien formé, commentaires honnêtes (« identifiants éphémères »,
  « à ne pas conserver hors build »). Le relecteur note que l'**intention** est
  saine ; il manque l'**étape qui matérialise** cette éphémérité (le cleanup).

### 5.4 Post-processor (L60–62)

- **`manifest`** : produit `lab-vm-manifest.json` (traçabilité du build : IDs
  d'artefacts, horodatage). **Bon réflexe** de provenance/traçabilité. On pourrait
  y adjoindre un checksum du qcow2 produit pour distribution vérifiable.

---

## 6. Constats transverses

**Intégrité des sources** : **contrasté** — la VM vérifie le **checksum** de
l'image cloud (bien, à renforcer par GPG), mais `portal.pkr.hcl` hérite des
téléchargements applicatifs et le dépôt a, ailleurs, des sources non vérifiées
(OpenSSL C11, GPG Docker). Harmoniser vers « toujours vérifier ».

**Reproductibilité** : menacée par `tag = "latest"`, l'ISO `current`, et les
contraintes de plugins `~> 1.1`. Épingler versions, ISO datée, et **versionner le
lockfile** Packer.

**Fuite de matériel enseignant** : `lab-vm` copie **tout le dépôt** (`../..`), donc
**`solutions/`**, dans une VM **remise à l'étudiant** → **corriger en priorité**
(exclusion ou cleanup). C'est l'exact symétrique du soin pris en mode 3 Ansible.

**Gestion des identifiants** : mot de passe de build **trivial, en clair,
non expiré, `sudo NOPASSWD`, `ssh_pwauth`** → acceptable seulement pour une VM
**isolée**, à **documenter** et idéalement à **nettoyer** avant livraison ; sortir
le secret du HCL versionné.

**Isolement à l'exécution** : objectif **atteint** — pré-build des images dans la
VM → fonctionnement **hors ligne**, sans dépendance aux dépôts EOL/externes.
C'est la grande qualité de la chaîne Packer.

**Cohérence avec le reste du dépôt** : deux divergences à trancher — `docker.io`
(Packer) vs `docker-ce` (Ansible) ; définition du portail **dupliquée**
(Dockerfile **et** `portal.pkr.hcl`). Choisir une source unique de vérité.

**Traçabilité** : `manifest` présent (bien) ; ajouter un checksum du livrable.

---

## 7. Recommandations d'amélioration (priorisées)

1. **(Critique)** Exclure `solutions/` (et tout matériel enseignant) du
   provisioning de `lab-vm`, ou l'effacer dans une étape de cleanup **avant** le
   commit du qcow2 — sinon les corrigés sont livrés aux étudiants.
2. **(Important)** Étape de **cleanup** de fin de build de la VM : purge des
   caches apt, de l'historique, des clés SSH host, **expiration/verrouillage** du
   compte de build, désactivation de `ssh_pwauth`.
3. **(Important)** Sortir le mot de passe de build du HCL versionné (variable
   sensible `PKR_VAR_…`) ; ne pas committer le hash associé à un secret trivial.
4. **(Reproductibilité)** Épingler : plugins en version exacte + **lockfile
   versionné** ; ISO cloud **datée** (pas `current`) ; remplacer `tag = "latest"`
   par un tag daté/sémantique.
5. **(Chaîne de confiance)** Vérifier la **signature GPG** du `SHA256SUMS`
   Canonical, en plus du checksum.
6. **(Cohérence)** Trancher `docker.io` vs `docker-ce` (aligner sur Ansible) ; et
   faire du **Dockerfile la source unique** de l'image portail (éviter la
   duplication avec `portal.pkr.hcl`).
7. **(Hygiène)** Aligner `portal.pkr.hcl` sur le Dockerfile (`--no-cache-dir`) ;
   filtrer `../app/` avant copie ; câbler ou retirer `lab_domain`.
8. **(Traçabilité)** Ajouter un checksum du qcow2 au `manifest` pour une
   distribution vérifiable.

---

## Annexe A — Flashcards (revue Packer)

1. **Q :** Dans quel ordre lit-on un projet Packer HCL2 ?
   **R :** `plugins` → `variables` → `source` (base + intégrité + identifiants) →
   `build` (provisioners, post-processors) → données d'amorçage (`http/user-data`).

2. **Q :** Quel est le défaut le plus grave de la chaîne Packer ici ?
   **R :** `lab-vm` copie **tout le dépôt** (`../..`), donc **`solutions/`**, dans
   une VM **remise à l'étudiant** → fuite des corrigés ; à exclure ou nettoyer.

3. **Q :** Qu'est-ce qui est **bien fait** côté intégrité dans `lab-vm` ?
   **R :** `iso_checksum = "file:…/SHA256SUMS"` → l'image cloud de base est
   **vérifiée** (à renforcer par la signature GPG Canonical).

4. **Q :** Pourquoi `tag = "latest"` et l'ISO `current` posent-ils problème ?
   **R :** Ils cassent la **reproductibilité** : deux builds à dates différentes
   partent/produisent des artefacts différents. Épingler des versions datées.

5. **Q :** Le mot de passe de build `labtp` est-il acceptable ?
   **R :** Seulement parce que la VM est **isolée/hors ligne** ; il faut le
   **documenter**, idéalement l'**expirer/verrouiller** en fin de build et
   désactiver `ssh_pwauth`, et le sortir du HCL versionné.

6. **Q :** Pourquoi pré-construire les images dans la VM (`docker compose build`)
   est-il un point fort ?
   **R :** La VM tourne ensuite **hors ligne**, sans dépendance aux dépôts EOL/
   externes → **isolement garanti** à l'exécution.

7. **Q :** Quelle duplication la revue signale-t-elle et pourquoi ?
   **R :** L'image portail est définie **deux fois** (Dockerfile **et**
   `portal.pkr.hcl`) → risque de **dérive** ; viser une **source unique de
   vérité**.

8. **Q :** Que signifie `usermod -aG docker lab` en matière de privilèges ?
   **R :** `lab` devient membre du groupe `docker` → **équivalent root** sans mot
   de passe ; acceptable pour un **bac à sable personnel** isolé, à documenter.

9. **Q :** À quoi sert le post-processor `manifest` ?
   **R :** À la **traçabilité** du build (IDs d'artefacts, horodatage) ; on peut y
   ajouter un checksum du qcow2 pour une distribution vérifiable.

10. **Q :** Pourquoi versionner le lockfile Packer ?
    **R :** Pour figer les **versions exactes de plugins** résolues et garantir
    des builds reproductibles dans l'équipe et dans le temps.

## Annexe B — Glossaire des acronymes

| Acronyme | Développé | Explication |
|----------|-----------|-------------|
| **HCL** | *HashiCorp Configuration Language* | Langage de configuration de Packer (v2) et Terraform. |
| **VM** | *Virtual Machine* | Livrable qcow2 autonome remis en salle. |
| **QEMU** | *Quick EMUlator* | Builder Packer produisant la VM ; s'appuie sur KVM. |
| **KVM** | *Kernel-based Virtual Machine* | Accélération de virtualisation Linux (`accelerator="kvm"`). |
| **ISO** | *(image disque)* | Image cloud de base ; ici le `.img` Ubuntu jammy. |
| **qcow2** | *QEMU Copy-On-Write v2* | Format de disque de la VM produite. |
| **SSH** | *Secure Shell* | Accès de provisioning à la VM en cours de build. |
| **SMBIOS** | *System Management BIOS* | Vecteur d'injection du *datasource* cloud-init (`nocloud-net`). |
| **TOFU** | *Trust On First Use* | Confiance accordée à la première récupération (checksum servi par la même origine). |
| **GPG** | *GNU Privacy Guard* | Signature qui renforcerait la confiance dans `SHA256SUMS`. |
| **EOL** | *End Of Life* | Dépôts en fin de vie évités grâce au pré-build hors ligne. |
| **CE** | *Community Edition* | Docker CE (Ansible) vs `docker.io` (Packer) — divergence à trancher. |
| **IaC** | *Infrastructure as Code* | Paradigme immuable revendiqué (Morris, 2020). |

---

## Références

[1] HashiCorp, *Packer Documentation — HCL2 blocks (`source`, `build`,
    `provisioner`, `post-processor`)*, developer.hashicorp.com/packer.
[2] HashiCorp, *Packer — `required_plugins` & `packer init`, lock file*,
    developer.hashicorp.com/packer.
[3] Docker, *Best practices — avoid `latest` for reproducible builds*,
    docs.docker.com.
[4] K. Morris, *Infrastructure as Code: Dynamic Systems for the Cloud Age*, 2ᵉ éd.,
    O'Reilly, 2020 (images immuables, provenance).
[5] Canonical, *Ubuntu Cloud Images & SHA256SUMS(.gpg)* ; cloud-init,
    *NoCloud datasource*, cloudinit.readthedocs.io.
[6] NIST SP 800-190, *Application Container Security Guide* (chaîne de build,
    provenance des images).

---
*Revue de code à usage interne — ANSSI / CFSSI. La VM de salle est un bac à sable
**isolé et hors ligne** ; les identifiants d'amorçage permissifs ne sont
acceptables que dans ce cadre et doivent être documentés — et, idéalement,
nettoyés avant distribution.*
