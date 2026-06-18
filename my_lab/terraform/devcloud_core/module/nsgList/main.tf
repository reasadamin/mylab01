resource "oci_core_network_security_group" "this" {
  for_each = var.nsg_names

  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = each.value
  freeform_tags  = merge(var.freeform_tags, { name = each.value })
}