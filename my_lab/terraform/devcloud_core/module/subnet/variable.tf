variable "compartment_id" {
  description = "OCID of the compartment the subnets are created in."
  type        = string
}

variable "vcn_id" {
  description = "OCID of the VCN the subnets belong to."
  type        = string
}

variable "vcn_cidr" {
  description = "Primary CIDR block of the VCN. Subnet CIDRs are derived from this with cidrsubnet()."
  type        = string
}

variable "route_table_id" {
  description = "OCID of the route table associated with the subnets."
  type        = string
}

variable "subnets" {
  description = <<-EOT
    Map of subnet display name => settings. The CIDR is derived from vcn_cidr as
    cidrsubnet(vcn_cidr, newbits, netnum). For a /21 VCN, newbits = 3 yields /24 blocks.
    dns_label is optional (alphanumeric, max 15 chars, unique within the VCN).
  EOT
  type = map(object({
    newbits   = number
    netnum    = number
    dns_label = optional(string)
  }))
  default = {
    "dbdev-a" = { newbits = 3, netnum = 0, dns_label = "dbdeva" }
    "dbdev-b" = { newbits = 3, netnum = 1, dns_label = "dbdevb" }
    "dbdev-c" = { newbits = 3, netnum = 2, dns_label = "dbdevc" }
  }
}

variable "prohibit_public_ip_on_vnic" {
  description = "If true, VNICs in the subnet cannot be assigned a public IP (private subnet)."
  type        = bool
  default     = true
}

variable "freeform_tags" {
  description = "Freeform tags applied to every subnet."
  type        = map(string)
  default     = { Team = "DBA" }
}