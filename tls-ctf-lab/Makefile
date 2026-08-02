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
