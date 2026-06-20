variable "compartment_id" {
  description = "OCID of the compartment the policy is attached to. Must be an ancestor of (or equal to) the compartment named in the statements."
  type        = string
}

variable "compartment_name" {
  description = "Name of the compartment the statements grant access to."
  type        = string
}

variable "dba_group_ocid" {
  description = "OCID of the IAM group the policy grants permissions to."
  type        = string
}

variable "policy_name" {
  description = "Name of the IAM policy."
  type        = string
  default     = "DBA_compartment_policy_01"
}

variable "policy_description" {
  description = "Description of the IAM policy."
  type        = string
  default     = "DBA compartment policy"
}

variable "freeform_tags" {
  description = "Freeform tags applied to the policy."
  type        = map(string)
  default     = { Team = "DBA" }
}