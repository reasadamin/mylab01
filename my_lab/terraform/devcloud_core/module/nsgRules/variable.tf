variable "nsg_ids" {
  description = "Map of NSG display name => OCID. Wire this from the nsgList module's nsg_ids output."
  type        = map(string)
}

variable "nsg_rules" {
  description = <<-EOT
    Map of rule key => security rule definition.
      nsg_name    : must match a key in nsg_ids.
      direction   : "INGRESS" or "EGRESS".
      protocol    : "6" (TCP), "17" (UDP), "1" (ICMP), or "all".
      remote      : CIDR, service label, or NSG OCID depending on remote_type.
      remote_type : "CIDR_BLOCK", "SERVICE_CIDR_BLOCK", or "NETWORK_SECURITY_GROUP".
      port        : optional TCP destination port range (only applied when protocol = "6").
  EOT
  type = map(object({
    nsg_name    = string
    description = optional(string, "")
    direction   = string
    protocol    = string
    remote      = string
    remote_type = string
    port = optional(object({
      min = number
      max = number
    }))
  }))
  default = {
    "yum_https" = {
      nsg_name    = "oci_yum_nsg"
      description = "Allow HTTPS egress to OCI services via Service Gateway"
      direction   = "EGRESS"
      protocol    = "6"
      remote      = "all-bom-services-in-oracle-services-network"
      remote_type = "SERVICE_CIDR_BLOCK"
      port        = { min = 443, max = 443 }
    }
    "yum_http" = {
      nsg_name    = "oci_yum_nsg"
      description = "Allow HTTP egress to OCI services via Service Gateway"
      direction   = "EGRESS"
      protocol    = "6"
      remote      = "all-bom-services-in-oracle-services-network"
      remote_type = "SERVICE_CIDR_BLOCK"
      port        = { min = 80, max = 80 }
    }
    "mail_https" = {
      nsg_name    = "mail01_omd_nsg"
      description = "Allow HTTPS egress to mail network"
      direction   = "EGRESS"
      protocol    = "6"
      remote      = "192.168.10.0/24"
      remote_type = "CIDR_BLOCK"
      port        = { min = 443, max = 443 }
    }
    "proxy_https" = {
      nsg_name    = "proxy01_omd_nsg"
      description = "Allow HTTPS egress to proxy network"
      direction   = "EGRESS"
      protocol    = "6"
      remote      = "192.168.10.0/24"
      remote_type = "CIDR_BLOCK"
      port        = { min = 443, max = 443 }
    }
    "mgmt_https" = {
      nsg_name    = "mgmt_omd_nsg"
      description = "Allow HTTPS egress to management network"
      direction   = "EGRESS"
      protocol    = "6"
      remote      = "192.168.20.0/24"
      remote_type = "CIDR_BLOCK"
      port        = { min = 443, max = 443 }
    }
  }
}