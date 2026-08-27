packer {
  required_plugins {
    qemu = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "ssh_pub_key" {
  type    = string
  default = env("SSH_PUB_KEY")
}

source "qemu" "prof" {
  iso_url      = "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img"
  iso_checksum = "file:https://cloud-images.ubuntu.com/releases/22.04/release/SHA256SUMS"
  
  disk_image       = true
  disk_size        = "20G"
  format           = "qcow2"
  output_directory = "../output/prof_standalone/"
  vm_name          = "packer-prof-standalone.qcow2"

  memory           = 2048
  cpus             = 2

  ssh_username = "ansible"
  ssh_password = "ansible"
  ssh_timeout  = "5m"

  cd_content = {
    "user-data" = templatefile("${path.root}/http/user-data", {
      ssh_pub_key = var.ssh_pub_key
    })
    "meta-data" = ""
  }
  cd_label = "cidata"
}

build {
  sources = ["source.qemu.prof"]

  # 1. Installation des paquets de base
  provisioner "shell" {
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive",
      "NEEDRESTART_MODE=a"
    ]
    inline = [
      "sudo sed -i 's/#$nrconf{restart} = .*/$nrconf{restart} = \"a\";/' /etc/needrestart/needrestart.conf 2>/dev/null || true",
      "sudo apt-get update",
      "sudo -E apt-get install -y ca-certificates curl gnupg rsync git"
    ]
  }

  # 2. Docker
  provisioner "shell" {
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive",
      "NEEDRESTART_MODE=a"
    ]
    inline = [
      "sudo install -m 0755 -d /etc/apt/keyrings",
      "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg",
      "sudo chmod a+r /etc/apt/keyrings/docker.gpg",
      "echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable\" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null",
      "sudo apt-get update",
      "sudo -E apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
      "sudo usermod -aG docker ansible",
      "sudo systemctl enable docker"
    ]
  }

  # 3. Répertoire de travail
  provisioner "shell" {
    inline = [
      "sudo mkdir -p /home/ansible/tls-ctf-lab",
      "sudo chown -R ansible:ansible /home/ansible/tls-ctf-lab",
      "sudo mkdir -p /opt/tls-lab/captures",
      "sudo chown -R ansible:ansible /opt/tls-lab"      
    ]
  }
}