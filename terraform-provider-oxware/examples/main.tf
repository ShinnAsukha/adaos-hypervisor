terraform {
  required_providers {
    oxware = {
      source  = "ShinnAsukha/oxware"
      version = "~> 1.0"
    }
  }
}

provider "oxware" {
  url   = "https://oxware.example.com"   # veya OXWARE_URL env
  token = var.oxware_token               # veya OXWARE_TOKEN env
}

variable "oxware_token" {
  sensitive = true
}

# Mevcut VM'leri listele
data "oxware_vms" "all" {}

output "vm_names" {
  value = [for v in data.oxware_vms.all.vms : v.name]
}

# Yeni VM oluştur
resource "oxware_vm" "web" {
  name      = "web-server-01"
  vcpus     = 2
  memory_mb = 2048
  disk_gb   = 20
  network   = "default"
  os_variant = "ubuntu22.04"

  # cloud-init ile otomatik yapılandır
  cloud_init_user     = "ubuntu"
  cloud_init_password = "changeme"
  cloud_init_ssh_key  = file("~/.ssh/id_rsa.pub")
  cloud_init_hostname = "web-server-01"
}

output "web_vm_id"    { value = oxware_vm.web.id }
output "web_vnc_port" { value = oxware_vm.web.vnc_port }
