# ---- Provider / authentication ----
variable "oci_profile" {
  description = "Profile name in ~/.oci/config used for authentication."
  type        = string
  default     = "DEFAULT"
}

variable "region" {
  description = "OCI region identifier (e.g. ap-mumbai-1)."
  type        = string
  default     = "ap-mumbai-1"
}

variable "tenancy_ocid" {
  description = "OCID of the tenancy. Used as the root compartment for the new compartment."
  type        = string
}

# ---- Networking ----
variable "drg_ocid" {
  description = "OCID of the Dynamic Routing Gateway used for on-prem / peered routes."
  type        = string
}

# ---- IAM ----
variable "dba_group_ocid" {
  description = "OCID of the DBA IAM group granted access to the compartment."
  type        = string
}