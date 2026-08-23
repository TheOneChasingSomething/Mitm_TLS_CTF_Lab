# Raccourcis d'exploitation du laboratoire.
.PHONY: build up down logs clean packer-portal packer-vm rotate-flags classroom classroom-check centralized-instances debug debug-down generate-keys deploy-ansible-prof-centralized deploy-ansible-prof-standalone setup-vm-packer-prof-centralized setup-vm-packer-prof-standalone

SSH_KEY_FILE := $(HOME)/.ssh/id_ed25519
STUDENTS_FILE := students.txt

# --- Configuration des artefacts VM ---
OUT_DIR_CENTRAL := packer/output/prof_centralized
VM_NAME_CENTRAL := packer-prof-centralized.qcow2

OUT_DIR_STANDALONE := packer/output/prof_standalone
VM_NAME_STANDALONE := packer-prof-standalone.qcow2

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

generate-keys:    ## Génère les clés SSH pour la liste d'étudiants définie dans students.txt
	@if [ ! -f $(STUDENTS_FILE) ]; then \
		echo "etu01\netu02\netu03" > $(STUDENTS_FILE); \
		echo "[+] Fichier $(STUDENTS_FILE) créé avec 3 étudiants par défaut."; \
	fi
	@mkdir -p keys
	@while IFS= read -r etu || [ -n "$$etu" ]; do \
		[ -z "$$etu" ] && continue; \
		if [ ! -f keys/$$etu ]; then \
			ssh-keygen -t ed25519 -N "" -f keys/$$etu -C "$$etu@tp" >/dev/null; \
			echo "[+] Clé générée pour $$etu"; \
		fi; \
	done < $(STUDENTS_FILE)

deploy-ansible-prof-centralized: generate-keys ## Déploie Ansible (mode centralisé multi-étudiants)
	@STUDENT_JSON=$$(python3 -c 'import json, glob; print(json.dumps({"student_instances": [{"login": f.split("/")[-1].replace(".pub",""), "ssh_pubkey": open(f).read().strip()} for f in glob.glob("keys/*.pub")]}))') && \
	if [ -f venv/bin/activate ]; then . venv/bin/activate; elif [ -f ../venv/bin/activate ]; then . ../venv/bin/activate; else echo "[!] Erreur : Aucun venv trouvé."; exit 1; fi && \
	cd ansible && \
	echo "--> 6a. Validation accès prof..." && \
	ansible prof_host -m ping -i inventory.ini || exit 1 && \
	echo "--> 6b. Validation de la syntaxe..." && \
	ansible-playbook centralized.yml -i inventory.ini --syntax-check || exit 1 && \
	echo "--> 6c. Déploiement du playbook centralized..." && \
	ansible-playbook centralized.yml -i inventory.ini -e "$$STUDENT_JSON" || exit 1 && \
	echo "--> 6d. Vérification de l'accès SSH des étudiants..." && \
	while IFS= read -r etu || [ -n "$$etu" ]; do \
		[ -z "$$etu" ] && continue; \
		if ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i ../keys/$$etu -q tp-$$etu@127.0.0.1 "echo ok" >/dev/null 2>&1; then \
			echo "   [✓] Connexion SSH OK pour $$etu"; \
		else \
			echo "   [!] ERREUR : Échec de la connexion SSH pour $$etu"; exit 1; \
		fi; \
	done < ../$(STUDENTS_FILE)

deploy-ansible-prof-standalone: ## Déploie Ansible (mode autonome all-in-one)
	@if [ -f venv/bin/activate ]; then . venv/bin/activate; elif [ -f ../venv/bin/activate ]; then . ../venv/bin/activate; else echo "[!] Erreur : Aucun venv trouvé."; exit 1; fi && \
	cd ansible && \
	echo "--> 6a. Validation accès prof..." && \
	ansible prof_host -m ping -i inventory.ini || exit 1 && \
	echo "--> 6b. Validation de la syntaxe..." && \
	ansible-playbook standalone.yml -i inventory.ini --syntax-check || exit 1 && \
	echo "--> 6c. Déploiement du playbook standalone..." && \
	ansible-playbook standalone.yml -i inventory.ini

setup-vm-packer-prof-centralized: generate-keys ## Prépare la VM prof et déploie le mode centralisé
	@echo "==> 1. Nettoyage d'une ancienne VM QEMU et suppression des anciens artefacts"
	-@pkill -f "qemu-system-x86_64.*$(OUT_DIR_CENTRAL)" || true
	rm -rf $(OUT_DIR_CENTRAL)
	@echo "==> 2. Génération de la clé SSH prof si absente"
	@if [ ! -f $(SSH_KEY_FILE) ]; then \
		ssh-keygen -t ed25519 -N "" -f $(SSH_KEY_FILE); \
	fi
	@echo "==> 3. Lancement de Packer avec la clé SSH injectée"
	cd packer/prof_centralized && \
	export SSH_PUB_KEY="$$(cat $(SSH_KEY_FILE).pub)" && \
	packer init . && \
	packer build -force -var-file=variables.pkrvars.hcl -only='qemu.*' .
	@echo "==> 4. Démarrage de la VM QEMU en mode NAT (Port forwarding 2222 -> 22)"
	qemu-system-x86_64 -enable-kvm -hda $(OUT_DIR_CENTRAL)/$(VM_NAME_CENTRAL) -k fr -m 2G -cpu host \
		-netdev user,id=net0,hostfwd=tcp::2222-:22 \
		-device virtio-net-pci,netdev=net0 \
		-display gtk -daemonize
	@echo "==> 5. Attente du démarrage du port SSH sur localhost:2222..."
	@until nc -z -w 2 127.0.0.1 2222 2>/dev/null; do sleep 2; done
	@echo "==> Temporisation pour la stabilisation d'OpenSSH..."
	@sleep 5
	@ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "[127.0.0.1]:2222" >/dev/null 2>&1 || true
	@echo "==> 6. Validation d'Ansible et déploiement du rôle centralized"
	@$(MAKE) deploy-ansible-prof-centralized

setup-vm-packer-prof-standalone: ## Prépare la VM prof et déploie le mode autonome
	@echo "==> 1. Nettoyage d'une ancienne VM QEMU et suppression des anciens artefacts"
	-@pkill -f "qemu-system-x86_64.*$(OUT_DIR_STANDALONE)" || true
	rm -rf $(OUT_DIR_STANDALONE)
	@echo "==> 2. Génération de la clé SSH prof si absente"
	@if [ ! -f $(SSH_KEY_FILE) ]; then \
		ssh-keygen -t ed25519 -N "" -f $(SSH_KEY_FILE); \
	fi
	@echo "==> 3. Lancement de Packer avec la clé SSH injectée"
	cd packer/prof_standalone && \
	export SSH_PUB_KEY="$$(cat $(SSH_KEY_FILE).pub)" && \
	packer init . && \
	packer build -force -var-file=variables.pkrvars.hcl -only='qemu.*' .
	@echo "==> 4. Démarrage de la VM QEMU en mode NAT (Port forwarding 2222 -> 22)"
	qemu-system-x86_64 -enable-kvm -hda $(OUT_DIR_STANDALONE)/$(VM_NAME_STANDALONE) -k fr -m 2G -cpu host \
		-netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::5000-:5000 \
		-device virtio-net-pci,netdev=net0 \
		-display gtk -daemonize
	@echo "==> 5. Attente du démarrage du port SSH sur localhost:2222..."
	@until nc -z -w 2 127.0.0.1 2222 2>/dev/null; do sleep 2; done
	@echo "==> Temporisation pour la stabilisation d'OpenSSH..."
	@sleep 5
	@ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "[127.0.0.1]:2222" >/dev/null 2>&1 || true
	@echo "==> 6. Validation d'Ansible et déploiement du playbook standalone"
	@$(MAKE) deploy-ansible-prof-standalone