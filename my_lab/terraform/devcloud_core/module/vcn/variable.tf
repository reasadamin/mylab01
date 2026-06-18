variable "compartment_id" {
  description = "OCID of the compartment the VCN is created in."
  type        = string
}

variable "vcn_cidr_blocks" {
  description = "List of IPv4 CIDR blocks assigned to the VCN."
  type        = list(string)
  default     = ["10.242.8.0/21"]
}

variable "vcn_display_name" {
  description = "Display name of the VCN."
  type        = string
  default     = "dbdev_vcn"
}

variable "vcn_dns_label" {
  description = "DNS label for the VCN's internal resolver"
  type        = string
  default     = "dbdevvcn"
}

variable "freeform_tags" {
  description = "Freeform tags applied to the VCN."
  type        = map(string)
  default     = { Team = "DBA" }
}