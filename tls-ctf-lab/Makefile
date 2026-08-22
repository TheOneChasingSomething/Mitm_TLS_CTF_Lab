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

SSH_KEY_FILE := $(HOME)/.ssh/id_ed25519_tmp_packer

setup-vm-packer-prof-standalone: ## Prépare SSH, le réseau, la VM et valide Ansible
	@echo "==> 1. Nettoyage d'une ancienne VM QEMU et suppression des anciens artefacts"
	-@pkill -f "qemu-system-x86_64.*output-prof-vm" || true
	rm -rf packer/prof_centralized/output-prof-vm
	@echo "==> 2. Génération de la clé SSH si absente"
	@if [ ! -f $(SSH_KEY_FILE) ]; then \
		ssh-keygen -t ed25519 -N "" -f $(SSH_KEY_FILE); \
	fi
	@echo "==> 3. Exécution du script de configuration du réseau"
	./scripts/setup-network-bridge.sh
	@echo "==> 4. Lancement de Packer avec la clé SSH injectée"
	cd packer/prof_centralized && \
	export SSH_PUB_KEY="$$(cat $(SSH_KEY_FILE).pub)" && \
	packer init . && \
	packer build -force -only='qemu.*' .
	@echo "==> 5. Ré-attachement de tap0 au bridge br0"
	sudo ip link set tap0 master br0
	sudo ip link set tap0 up
	@echo "==> 6. Démarrage de la VM QEMU en arrière-plan"
	qemu-system-x86_64 -enable-kvm -hda packer/prof_centralized/output-prof-vm/packer-prof -k fr -m 2G -cpu host \
		-netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
		-device virtio-net-pci,netdev=net0,mac=52:54:00:11:11:11 \
		-display gtk -daemonize
	@echo "==> 7. Attente du démarrage du port SSH (10.10.10.2:22)..."
	@until nc -z -w 2 10.10.10.2 22 2>/dev/null; do sleep 2; done
	@ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "10.10.10.2" >/dev/null 2>&1 || true
	@echo "==> 8. Validation de la connexion Ansible (ping)"
	@if [ -f venv/bin/activate ]; then \
		. venv/bin/activate && \
		if ! command -v ansible >/dev/null 2>&1; then \
			echo "[!] Erreur : Ansible n'est pas installé dans le venv (exécutez : pip install ansible)"; \
			exit 1; \
		fi && \
		cd ansible && ansible prof_vm -m ping -i inventory.ini; \
	elif [ -f ../venv/bin/activate ]; then \
		. ../venv/bin/activate && \
		if ! command -v ansible >/dev/null 2>&1; then \
			echo "[!] Erreur : Ansible n'est pas installé dans le venv (exécutez : pip install ansible)"; \
			exit 1; \
		fi && \
		cd ansible && ansible prof_vm -m ping -i inventory.ini; \
	else \
		echo "[!] Erreur : Aucun venv trouvé dans ./venv ou ../venv. Veuillez créer le venv et installer Ansible."; \
		exit 1; \
	fi