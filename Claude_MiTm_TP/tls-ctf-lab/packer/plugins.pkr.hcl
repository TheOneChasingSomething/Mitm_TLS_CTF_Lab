# Déclaration des plugins Packer requis (HCL2). Depuis Packer 1.7, les plugins
# sont externalisés et récupérés par `packer init`.
packer {
  required_plugins {
    docker = {
      source  = "github.com/hashicorp/docker"
      version = "~> 1.1"
    }
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1.1"
    }
  }
}
