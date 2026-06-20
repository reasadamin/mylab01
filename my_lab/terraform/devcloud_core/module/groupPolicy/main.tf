resource "oci_identity_policy" "this" {
  compartment_id = var.compartment_id
  name           = var.policy_name
  description    = var.policy_description
  freeform_tags  = var.freeform_tags

  statements = [
    "allow group id ${var.dba_group_ocid} to manage all-resources in compartment ${var.compartment_name}",
    "allow group id ${var.dba_group_ocid} to read virtual-network-family in compartment ${var.compartment_name}",
  ]
}