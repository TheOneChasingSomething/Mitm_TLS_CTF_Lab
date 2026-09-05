# Raccourcis d'exploitation du laboratoire.
.PHONY: local_build local_up local_down local_logs local_clean local_standalone_up local_attacker_shell local_ssh_student \
        packer-portal packer-vm rotate-flags classroom_check classroom deploy_network deploy_baremetal \
        deploy_baremetal_centralized debug local_debug local_debug_down generate-keys \
        setup-vm-packer-prof-centralized setup-vm-packer-prof-standalone \
        deploy-ansible-prof-centralized deploy-ansible-prof-standalone

SSH_KEY_FILE := $(HOME)/.ssh/id_ed25519
STUDENTS_FILE := students.txt

# --- Configuration des artefacts VM ---
OUT_DIR_CENTRAL := packer/output/prof_centralized
VM_NAME_CENTRAL := packer-prof-centralized.qcow2

OUT_DIR_STANDALONE := packer/output/prof_standalone
VM_NAME_STANDALONE := packer-prof-standalone.qcow2

# --- 1. GESTION DOCKER LOCAL (Préfixe local_) ---

local_build:            ## Construit toutes les images Docker localement
	docker compose build

local_up: local_build   ## Démarre le lab en local (Docker Compose)
	docker compose up -d
	@echo "Cibles locales : 8451(C1) 8453(C3) 8441(C4) 8442(C5) 8447(C6) 8448(C7) 8006/8443(C8) 8444(C9) 8446(C10) 8445(C11)"

local_down:             ## Arrête le lab local
	docker compose down

local_logs:             ## Suit les journaux Docker locaux
	docker compose logs -f

local_clean:            ## Arrête et purge volumes/images locaux
	docker compose down -v --rmi local

local_standalone_up: local_up ## Démarre le lab local et ouvre un terminal dans le conteneur attacker
	@echo "--> Connexion au conteneur attacker..."
	docker compose exec -it attacker bash

local_attacker-shell:   ## Ouvre un terminal dans le conteneur attacker local existant
	docker compose exec -it attacker bash

local_ssh-student:      ## Teste la connexion SSH étudiant vers la VM centralisée simulée (localhost:2222)
	@STUDENT=$${ETU:-etu01}; \
	echo "--> Connexion SSH en tant que tp-$$STUDENT sur localhost:2222..."; \
	ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i keys/$$STUDENT -p 2222 tp-$$STUDENT@127.0.0.1

# --- 2. GESTION PACKER & IMAGES ---

packer-portal:    ## Construit l'image portail via Packer→Docker
	cd packer && packer init . && packer build -only='docker.*' .

packer-vm:        ## Cuit la VM autonome via Packer→QEMU
	cd packer && packer init . && packer build -only='qemu.*' .

# --- 3. DÉPLOIEMENT ANSIBLE (Réseau, Baremetal, Centralisé) ---

classroom-check: ## Vérifie la syntaxe du playbook salle de TP
	cd ansible && ansible-playbook site.yml --syntax-check

classroom:        ## Déploie en salle de TP (Ansible : portail=prof, cibles=postes)
	cd ansible && ansible-galaxy collection install -r requirements.yml && ansible-playbook site.yml

deploy_network:   ## Déploie sur un réseau existant (VMs déjà créées, pas de QEMU local)
	@echo "--> Déploiement sur réseau existant (Baremetal/Cloud)..."
	@if [ -f venv/bin/activate ]; then . venv/bin/activate; elif [ -f ../venv/bin/activate ]; then . ../venv/bin/activate; else echo "[!] Erreur : Aucun venv trouvé."; exit 1; fi && \
	cd ansible && \
	echo "--> Validation accès prof..." && \
	ansible prof_host -m ping -i inventory.ini || exit 1 && \
	echo "--> Validation de la syntaxe..." && \
	ansible-playbook standalone.yml -i inventory.ini --syntax-check || exit 1 && \
	echo "--> Déploiement du playbook standalone..." && \
	ansible-playbook standalone.yml -i inventory.ini

deploy_baremetal: ## Déploie sur du matériel réel (Postes étudiants + Professeur)
	@echo "--> Déploiement Baremetal (Postes physiques)..."
	@$(MAKE) classroom

deploy_baremetal_centralized: ## Déploie le mode centralisé sur infra réelle (sans VM QEMU locale)
	@echo "--> Déploiement Centralisé sur infra réelle (Anti-triche)..."
	@STUDENT_JSON=$$(python3 -c 'import json, glob; print(json.dumps({"student_instances": [{"login": f.split("/")[-1].replace(".pub",""), "ssh_pubkey": open(f).read().strip()} for f in glob.glob("keys/*.pub")]}))') && \
	if [ -f venv/bin/activate ]; then . venv/bin/activate; elif [ -f ../venv/bin/activate ]; then . ../venv/bin/activate; else echo "[!] Erreur : Aucun venv trouvé."; exit 1; fi && \
	cd ansible && \
	echo "--> Validation accès prof..." && \
	ansible prof_host -m ping -i inventory.ini || exit 1 && \
	echo "--> Validation de la syntaxe..." && \
	ansible-playbook centralized.yml -i inventory.ini --syntax-check || exit 1 && \
	echo "--> Déploiement du playbook centralized..." && \
	ansible-playbook centralized.yml -i inventory.ini -e "$$STUDENT_JSON" || exit 1 && \
	echo "--> Vérification de l'accès SSH des étudiants..." && \
	while IFS= read -r etu || [ -n "$$etu" ]; do \
		[ -z "$$etu" ] && continue; \
		# Note: La vérification SSH nécessite que les étudiants soient accessibles sur le réseau réel
		echo "   [i] Vérification pour $$etu (à faire manuellement si hors réseau)"; \
	done < $(STUDENTS_FILE)

# --- 4. DEBUG LOCAL ---

local_debug:            ## Démarre le lab AVEC le proxy d'observation (UI: http://localhost:8081)
	docker compose -f docker-compose.yml -f docker-compose.debug.yml up -d --build
	@echo "Proxy d'inspection mitmweb : http://localhost:8081"

local_debug-down:       ## Arrête le lab lancé en mode debug
	docker compose -f docker-compose.yml -f docker-compose.debug.yml down

# --- 5. UTILITAIRES ---

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

define start_qemu_vm
	@img_path="$(1)/$(2)"; \
	if [ -f "$$img_path" ]; then \
		if pgrep -f "qemu-system-x86_64.*$$img_path" >/dev/null 2>&1; then \
			echo "--> VM QEMU ($$img_path) déjà en cours d'exécution."; \
		else \
			echo "--> Démarrage de la VM QEMU ($$img_path)..."; \
			qemu-system-x86_64 -enable-kvm -hda "$$img_path" -k fr -m 2G -cpu host \
				-netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::5000-:5000 \
				-device virtio-net-pci,netdev=net0 \
				-display gtk -daemonize; \
			echo "--> Attente du port SSH (127.0.0.1:2222)..."; \
			ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "[127.0.0.1]:2222" >/dev/null 2>&1 || true; \
			until ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i $(SSH_KEY_FILE) -p 2222 -q ansible@127.0.0.1 "echo ok" >/dev/null 2>&1; do \
				sleep 2; \
			done; \
			echo "--> [✓] VM démarrée et SSH prêt."; \
		fi; \
	else \
		echo "--> Avertissement : Image $$img_path introuvable. Lancez d'abord la cible setup-vm-packer-* correspondante."; \
	fi
endef

# --- 6. WORKFLOW COMPLET (Packer + QEMU + Ansible) ---

setup-vm-packer-prof-centralized: generate-keys ## Prépare la VM prof et déploie le mode centralisé (Local QEMU)
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
	@echo "==> 4. Démarrage de la VM QEMU en mode NAT (Port forwarding 2222 -> 22, 5000 -> 5000)"
	qemu-system-x86_64 -enable-kvm -hda $(OUT_DIR_CENTRAL)/$(VM_NAME_CENTRAL) -k fr -m 2G -cpu host \
		-netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::5000-:5000 \
		-device virtio-net-pci,netdev=net0 \
		-display gtk -daemonize
	@echo "==> 5. Attente de la disponibilité complète d'OpenSSH sur 127.0.0.1:2222..."
		@ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "[127.0.0.1]:2222" >/dev/null 2>&1 || true
		@until ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i $(SSH_KEY_FILE) -p 2222 -q ansible@127.0.0.1 "echo ok" >/dev/null 2>&1; do \
			echo "   [i] Attente de l'initialisation de la VM..."; \
			sleep 3; \
		done
		@echo "==> [✓] Service SSH de la VM opérationnel."
	@echo "==> 6. Validation d'Ansible et déploiement du rôle centralized"
	@$(MAKE) deploy-ansible-prof-centralized
	ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "[localhost]:2222" >/dev/null 2>&1 || true
	ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "[127.0.0.1]:2222" >/dev/null 2>&1 || true	

setup-vm-packer-prof-standalone: ## Prépare la VM prof et déploie le mode autonome (Local QEMU)
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
	PACKER_LOG=1 packer build -force -var-file=variables.pkrvars.hcl -only='qemu.*' .
	@echo "==> 4. Démarrage de la VM QEMU en mode NAT (Port forwarding 2222 -> 22, 5000 -> 5000)"
	qemu-system-x86_64 -enable-kvm -hda $(OUT_DIR_STANDALONE)/$(VM_NAME_STANDALONE) -k fr -m 2G -cpu host \
		-netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::5000-:5000 \
		-device virtio-net-pci,netdev=net0 \
		-display gtk -daemonize
	@echo "==> 5. Attente de la disponibilité complète d'OpenSSH sur 127.0.0.1:2222..."
		@ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "[127.0.0.1]:2222" >/dev/null 2>&1 || true
		@until ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i $(SSH_KEY_FILE) -p 2222 -q ansible@127.0.0.1 "echo ok" >/dev/null 2>&1; do \
			echo "   [i] Attente de l'initialisation de la VM..."; \
			sleep 3; \
		done
		@echo "==> [✓] Service SSH de la VM opérationnel."
	@echo "==> 6. Validation d'Ansible et déploiement du playbook standalone"
	@$(MAKE) deploy-ansible-prof-standalone
	ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "[localhost]:2222" >/dev/null 2>&1 || true
	ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "[127.0.0.1]:2222" >/dev/null 2>&1 || true

cloud_standalone: ## Installation complète Cloud Standalone (Init + Deploy)
	@echo "--> Démarrage de l'installation Cloud Standalone..."
	@# Étape 1 : Initialisation (Remplacement Packer : Docker, Git, etc.)
	@echo "   [1/2] Initialisation de la VM Cloud (Installation Docker & Prérequis)..."
	@if [ -f venv/bin/activate ]; then . venv/bin/activate; elif [ -f ../venv/bin/activate ]; then . ../venv/bin/activate; else echo "[!] Erreur : Aucun venv trouvé."; exit 1; fi && \
	cd ansible && \
	ansible-playbook init.yml -i inventory.ini  || { echo "[!] Échec de l'initialisation."; exit 1; }
	
	@# Étape 2 : Déploiement des cibles
	@echo "   [2/2] Déploiement des cibles CTF (Standalone)..."
	@if [ -f venv/bin/activate ]; then . venv/bin/activate; elif [ -f ../venv/bin/activate ]; then . ../venv/bin/activate; else echo "[!] Erreur : Aucun venv trouvé."; exit 1; fi && \
	cd ansible && \
	ansible-playbook standalone.yml -i inventory.ini || { echo "[!] Échec du déploiement."; exit 1; }
	
	@echo "--> [✓] Installation Cloud Standalone terminée avec succès."
	@echo "--> Vous pouvez maintenant accéder aux cibles via le portail ou les ports exposés."

# --- Blocs à ajouter dans la section 3 (DÉPLOIEMENT ANSIBLE) ---

deploy-ansible-prof-standalone: ## Déploie le mode standalone via Ansible sur la VM Packer locale (QEMU)
	@echo "--> Déploiement Ansible sur VM Packer Standalone (127.0.0.1:2222)..."
	@if [ -f venv/bin/activate ]; then . venv/bin/activate; elif [ -f ../venv/bin/activate ]; then . ../venv/bin/activate; else echo "[!] Erreur : Aucun venv trouvé."; exit 1; fi && \
	cd ansible && \
	ansible-playbook standalone.yml -i inventory_packer.ini

deploy-ansible-prof-centralized: generate-keys ## Déploie le mode centralisé via Ansible sur la VM Packer locale (QEMU)
	@echo "--> Déploiement Ansible sur VM Packer Centralisé (127.0.0.1:2222)..."
	@STUDENT_JSON=$$(python3 -c 'import json, glob; print(json.dumps({"student_instances": [{"login": f.split("/")[-1].replace(".pub",""), "ssh_pubkey": open(f).read().strip()} for f in glob.glob("keys/*.pub")]}))') && \
	if [ -f venv/bin/activate ]; then . venv/bin/activate; elif [ -f ../venv/bin/activate ]; then . ../venv/bin/activate; else echo "[!] Erreur : Aucun venv trouvé."; exit 1; fi && \
	cd ansible && \
	ansible-playbook centralized.yml -i inventory_packer.ini -e "$$STUDENT_JSON"

# Alias pour les anciennes commandes (optionnel, pour compatibilité)
build: local_build
up: local_up
down: local_down
logs: local_logs
clean: local_clean
standalone-up: local_standalone_up
attacker-shell: local_attacker-shell
ssh-student: local_ssh-student
debug: local_debug
debug-down: local_debug-down