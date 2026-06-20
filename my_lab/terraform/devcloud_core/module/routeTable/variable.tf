variable "compartment_id" {
  description = "OCID of the compartment the route table is created in."
  type        = string
}

variable "vcn_id" {
  description = "OCID of the VCN the route table belongs to."
  type        = string
}

variable "display_name" {
  description = "Display name of the route table."
  type        = string
  default     = "default_rt"
}

variable "service_gateway_id" {
  description = "OCID of the Service Gateway used as the next hop for OCI service traffic."
  type        = string
}

variable "service_cidr_block" {
  description = "Service CIDR label for the Service Gateway route (e.g. 'all-<region>-services-in-oracle-services-network'). Wire this from the serviceGateway module output."
  type        = string
  default     = "all-bom-services-in-oracle-services-network"
}

variable "drg_id" {
  description = "OCID of the Dynamic Routing Gateway used as the next hop for on-prem / peered networks."
  type        = string
}

variable "drg_route_cidrs" {
  description = "List of on-prem / peered CIDR blocks routed through the DRG."
  type        = list(string)
  default = [
    "10.10.0.0/16",   # BD VPN
    "192.168.0.0/16", # BD office
    "172.16.0.0/12",  # BD server
  ]
}

variable "freeform_tags" {
  description = "Freeform tags applied to the route table."
  type        = map(string)
  default     = { Team = "DBA" }
}