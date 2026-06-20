variable "compartment_id" {
  description = "OCID of the compartment the NAT gateway is created in."
  type        = string
}

variable "vcn_id" {
  description = "OCID of the VCN the NAT gateway belongs to."
  type        = string
}

variable "display_name" {
  description = "Display name of the NAT gateway."
  type        = string
  default     = "vcn_nat_gw"
}

variable "block_traffic" {
  description = "If true, traffic through the NAT gateway is blocked (gateway exists but passes no traffic). Useful as a kill switch."
  type        = bool
  default     = false
}

variable "public_ip_id" {
  description = "OCID of a reserved public IP to assign to the NAT gateway. Leave null to let OCI assign an ephemeral public IP automatically."
  type        = string
  default     = null
}

variable "route_table_id" {
  description = "OCID of the route table used for TRANSIT routing of traffic arriving at the NAT gateway. Leave null for a standard NAT gateway."
  type        = string
  default     = null
}

variable "freeform_tags" {
  description = "Freeform tags applied to the NAT gateway."
  type        = map(string)
  default     = { Team = "DBA" }
}