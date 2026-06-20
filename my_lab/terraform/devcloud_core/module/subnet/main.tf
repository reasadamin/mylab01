resource "oci_core_subnet" "this" {
  for_each = var.subnets

  compartment_id             = var.compartment_id
  vcn_id                     = var.vcn_id
  cidr_block                 = cidrsubnet(var.vcn_cidr, each.value.newbits, each.value.netnum)
  display_name               = each.key
  dns_label                  = each.value.dns_label
  route_table_id             = var.route_table_id
  prohibit_public_ip_on_vnic = var.prohibit_public_ip_on_vnic
  freeform_tags              = var.freeform_tags
}