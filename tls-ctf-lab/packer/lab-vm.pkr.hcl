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
  qemuargs = [
    ["-smbios", "type=1,serial=ds=nocloud-net;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/"],
  ]

  ssh_username     = "lab"
  ssh_password     = "labtp"
  ssh_timeout      = "20m"
  shutdown_command = "echo labtp | sudo -S shutdown -P now"
  vm_name          = "tls-lab.qcow2"
}

build {
  name    = "qemu"
  sources = ["source.qemu.lab"]

  # Dépôt du lab dans la VM.
  provisioner "file" {
    source      = "${path.root}/.."
    destination = "/home/lab/tls-ctf-lab"
  }

  # Installation de Docker et pré-construction des images (hors ligne ensuite).
  provisioner "shell" {
    inline = [
      "echo labtp | sudo -S apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-plugin",
      "sudo usermod -aG docker lab",
      "cd /home/lab/tls-ctf-lab && sudo docker compose build",
      "sudo systemctl enable docker",
    ]
  }

  # Empreinte de traçabilité du build.
  post-processor "manifest" {
    output = "lab-vm-manifest.json"
  }
}
