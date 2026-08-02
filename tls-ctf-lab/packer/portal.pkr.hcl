# Packer → Docker : construit l'image du PORTAIL par provisioning (démarre un
# conteneur de base, copie l'application, installe les dépendances, committe).
# Cette approche « immuable » (cf. Morris, Infrastructure as Code, 2020) produit
# une image reproductible et versionnée, indépendamment de docker build.
#
# Usage :
#   packer init .
#   packer build -only=docker.portal .

source "docker" "portal" {
  image  = "python:3.12-slim"
  commit = true
  changes = [
    "WORKDIR /srv",
    "USER lab",
    "EXPOSE 5000",
    "ENTRYPOINT [\"gunicorn\", \"-w\", \"2\", \"-b\", \"0.0.0.0:5000\", \"app:app\"]",
  ]
}

build {
  name    = "docker"
  sources = ["source.docker.portal"]

  # Copie de l'application dans le conteneur en cours de construction.
  provisioner "file" {
    source      = "${path.root}/../app/"
    destination = "/srv/"
  }

  provisioner "shell" {
    inline = [
      "pip install --no-cache-dir -r /srv/requirements.txt",
      "useradd -r -u 10001 lab || true",
      "mkdir -p /data/keys && chown -R lab /srv /data",
    ]
  }

  # Étiquetage local ; ajouter un post-processor docker-push pour un registry.
  post-processor "docker-tag" {
    repository = "${var.registry}/portal"
    tags       = [var.tag]
  }
}
