# Raccourcis d'exploitation du laboratoire.
.PHONY: build up down logs clean packer-portal packer-vm rotate-flags classroom classroom-check centralized-instances debug debug-down

build:            ## Construit toutes les images
	docker compose build

up: build         ## Démarre le lab
	docker compose up -d
	@echo "Cibles : 8451(C1) 8453(C3) 8441(C4) 8442(C5) 8447(C6) 8448(C7) 8006/8443(C8) 8444(C9) 8446(C10) 8445(C11) ; C2=balise Scapy interne"

down:             ## Arrête le lab
	docker compose down

logs:             ## Suit les journaux
	docker compose logs -f

clean:            ## Arrête et purge volumes/images
	docker compose down -v --rmi local

packer-portal:    ## Construit l'image portail via Packer→Docker
	cd packer && packer init . && packer build -only='docker.*' .

packer-vm:        ## Cuit la VM autonome via Packer→QEMU
	cd packer && packer init . && packer build -only='qemu.*' .

rotate-flags:     ## Régénère des flags uniques par promotion (exemple)
	@echo "Surchargez FLAG_C1..FLAG_C11 dans un .env puis: docker compose up -d --build --force-recreate"

classroom-check: ## Vérifie la syntaxe du playbook salle de TP
	cd ansible && ansible-playbook site.yml --syntax-check

classroom:        ## Déploie en salle de TP (Ansible : portail=prof, cibles=postes)
	cd ansible && ansible-galaxy collection install -r requirements.yml && ansible-playbook site.yml

centralized-instances: ## Déploie le mode centralisé anti-triche (une instance isolée/étudiant, accès SSH)
	cd ansible && ansible-galaxy collection install -r requirements.yml && ansible-playbook centralized.yml

debug:            ## Démarre le lab AVEC le proxy d'observation (UI: http://localhost:8081)
	docker compose -f docker-compose.yml -f docker-compose.debug.yml up -d --build
	@echo "Proxy d'inspection mitmweb : http://localhost:8081 (tout le trafic victime y transite)"

debug-down:       ## Arrête le lab lancé en mode debug
	docker compose -f docker-compose.yml -f docker-compose.debug.yml down
SSH_KEY_FILE := $(HOME)/.ssh/id_ed25519

setup-vm-packer-prof-standalone: ## Prépare SSH, la VM en NAT et valide Ansible
	@echo "==> 1. Nettoyage d'une ancienne VM QEMU et suppression des anciens artefacts"
	-@pkill -f "qemu-system-x86_64.*output-prof-vm" || true
	rm -rf packer/prof_centralized/output-prof-vm
	@echo "==> 2. Génération de la clé SSH si absente"
	@if [ ! -f $(SSH_KEY_FILE) ]; then \
		ssh-keygen -t ed25519 -N "" -f $(SSH_KEY_FILE); \
	fi
	@echo "==> 3. Lancement de Packer avec la clé SSH injectée"
	cd packer/prof_centralized && \
	export SSH_PUB_KEY="$$(cat $(SSH_KEY_FILE).pub)" && \
	packer init . && \
	packer build -force -only='qemu.*' .
	@echo "==> 4. Démarrage de la VM QEMU en mode NAT (Port forwarding 2222 -> 22)"
	qemu-system-x86_64 -enable-kvm -hda packer/prof_centralized/output-prof-vm/packer-prof.qcow2 -k fr -m 2G -cpu host \
		-netdev user,id=net0,hostfwd=tcp::2222-:22 \
		-device virtio-net-pci,netdev=net0 \
		-display gtk -daemonize
	@echo "==> 5. Attente du démarrage du port SSH sur localhost:2222..."
	@until nc -z -w 2 127.0.0.1 2222 2>/dev/null; do sleep 2; done
	@echo "==> Temporisation pour la stabilisation d'OpenSSH..."
	@sleep 5
	@ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "[127.0.0.1]:2222" >/dev/null 2>&1 || true
	@echo "==> 6. Validation de la connexion Ansible (ping)"
	@if [ -f venv/bin/activate ]; then \
		. venv/bin/activate && \
		if ! command -v ansible >/dev/null 2>&1; then \
			echo "[!] Erreur : Ansible n'est pas installé dans le venv"; exit 1; \
		fi && \
		cd ansible && ansible prof_host -m ping -i inventory.ini; \
	elif [ -f ../venv/bin/activate ]; then \
		. ../venv/bin/activate && \
		if ! command -v ansible >/dev/null 2>&1; then \
			echo "[!] Erreur : Ansible n'est pas installé dans le venv"; exit 1; \
		fi && \
		cd ansible && ansible prof_host -m ping -i inventory.ini; \
	else \
		echo "[!] Erreur : Aucun venv trouvé dans ./venv ou ../venv."; exit 1; \
	fi