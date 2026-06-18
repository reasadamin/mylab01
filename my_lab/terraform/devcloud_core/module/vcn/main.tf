resource "oci_core_vcn" "dbdev_vcn" {
  compartment_id = var.compartment_id
  cidr_blocks    = var.vcn_cidr_blocks
  display_name   = var.vcn_display_name
  dns_label      = var.vcn_dns_label
  freeform_tags  = var.freeform_tags
}