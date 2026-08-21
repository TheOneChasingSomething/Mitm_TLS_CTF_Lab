packer {
  required_plugins {
    qemu = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

source "qemu" "lab" {
  iso_url          = "https://releases.ubuntu.com/22.04/ubuntu-22.04.5-live-server-amd64.iso"
  iso_checksum     = "file:https://releases.ubuntu.com/22.04/SHA256SUMS"
  output_directory = "output-lab-vm"
  force            = true

  disk_size        = "20G"
  format           = "qcow2"
  memory           = 2048
  cpus             = 2

  ssh_username     = "lab"
  ssh_password     = "labtp"
  ssh_timeout      = "20m"

  # Adaptation selon ta configuration de boot (cloud-init / user-data)
  boot_wait        = "5s"
}

build {
  sources = ["source.qemu.lab"]

  # 1. Mise à jour du système et installation des paquets de base
  provisioner "shell" {
    inline = [
      "echo labtp | sudo -S apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg rsync git"
    ]
  }

  # 2. Ajout du dépôt officiel Docker et installation du moteur
  provisioner "shell" {
    inline = [
      "sudo install -m 0755 -d /etc/apt/keyrings",
      "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg",
      "sudo chmod a+r /etc/apt/keyrings/docker.gpg",
      "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable\" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null",
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
      "sudo usermod -aG docker lab",
      "sudo systemctl enable docker"
    ]
  }

  # 3. Préparation du répertoire de travail pour Ansible
  provisioner "shell" {
    inline = [
      "mkdir -p /home/lab/tls-ctf-lab",
      "chown -R lab:lab /home/lab/tls-ctf-lab"
    ]
  }
}