variable "compartment_id" {
  description = "OCID of the compartment the Service Gateway is created in."
  type        = string
}

variable "vcn_id" {
  description = "OCID of the VCN the Service Gateway attaches to."
  type        = string
}

variable "display_name" {
  description = "Display name of the Service Gateway."
  type        = string
  default     = "vcn_svc_gw"
}

variable "freeform_tags" {
  description = "Freeform tags applied to the Service Gateway."
  type        = map(string)
  default     = { Team = "DBA" }
}