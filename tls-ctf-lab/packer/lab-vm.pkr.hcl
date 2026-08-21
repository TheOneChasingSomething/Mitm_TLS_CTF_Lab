# Packer → QEMU : cuit une MACHINE VIRTUELLE autonome embarquant l'ensemble du
# laboratoire (Docker + docker-compose + les 5 cibles). Livrable idéal pour une
# salle de TP : un unique qcow2 remis à chaque étudiant, sans dépendance réseau
# à l'exécution → isolement garanti.
#
# Prérequis : une image cloud Ubuntu 22.04 (jammy) + un fichier cloud-init
# (http/user-data) fournissant l'utilisateur SSH. Voir README §VM.
#
# Usage :
#   packer init .
#   packer build -only=qemu.lab .

source "qemu" "lab" {
  iso_url          = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
  iso_checksum     = "file:https://cloud-images.ubuntu.com/jammy/current/SHA256SUMS"
  disk_image       = true
  output_directory = "output-lab-vm"
  format           = "qcow2"
  disk_size        = "12G"
  memory           = 2048
  cpus             = 2
  accelerator      = "kvm"
  headless         = true

  # Amorçage cloud-init (identifiants SSH du build).
  http_directory = "${path.root}/http"
  http_bind_address = "0.0.0.0"

qemuargs = [
    ["-smbios", "type=1,serial=ds=nocloud-net;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/"]
  ]

  ssh_username     = "lab"
  ssh_password     = "labtp"
  ssh_timeout      = "20m"
  ssh_clear_authorized_keys = true
  shutdown_command = "echo labtp | sudo -S shutdown -P now"
  vm_name          = "tls-lab.qcow2"
}

build {
  name    = "qemu"
  sources = ["source.qemu.lab"]

  # 1. Précréation du dossier cible sur la VM
  provisioner "shell" {
    inline = ["mkdir -p /home/lab/tls-ctf-lab"]
  }

  # 2. Copie du contenu du dépôt
  provisioner "file" {
    source      = "${path.root}/../"
    destination = "/home/lab/tls-ctf-lab/"
  }

# 3. Installation, build et lancement Docker
  provisioner "shell" {
    inline = [
      "echo labtp | sudo -S apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg",
      "sudo install -m 0755 -d /etc/apt/keyrings",
      "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg",
      "sudo chmod a+r /etc/apt/keyrings/docker.gpg",
      "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable\" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null",
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
      "sudo usermod -aG docker lab",
      "cd /home/lab/tls-ctf-lab && sudo docker compose -f docker-compose.yml build",
      "cd /home/lab/tls-ctf-lab && sudo docker compose -f docker-compose.yml up -d",
      "sudo systemctl enable docker"
    ]
  }

  post-processor "manifest" {
    output = "lab-vm-manifest.json"
  }
}
