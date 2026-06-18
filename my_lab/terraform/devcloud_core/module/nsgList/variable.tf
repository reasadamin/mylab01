variable "compartment_id" {
  description = "OCID of the compartment the NSGs are created in."
  type        = string
}

variable "vcn_id" {
  description = "OCID of the VCN the NSGs belong to."
  type        = string
}

variable "nsg_names" {
  description = "Set of Network Security Group display names to create in the VCN."
  type        = set(string)
  default = [
    "oci_yum_nsg",
    "mail01_omd_nsg",
    "proxy01_omd_nsg",
    "mgmt_omd_nsg",
  ]
}

variable "freeform_tags" {
  description = "Freeform tags applied to every NSG (merged with a per-NSG name tag)."
  type        = map(string)
  default     = { Team = "DBA" }
}