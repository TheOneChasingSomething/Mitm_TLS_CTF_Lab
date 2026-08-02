# Variables partagées. Surcharge : `packer build -var 'registry=registry.lab:5000' .`
variable "registry" {
  type        = string
  default     = "tls-lab"
  description = "Préfixe de dépôt/registry pour les images produites."
}

variable "tag" {
  type        = string
  default     = "latest"
  description = "Étiquette appliquée aux images."
}

variable "lab_domain" {
  type    = string
  default = "bank.tp.lan"
}
