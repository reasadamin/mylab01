resource "oci_core_route_table" "this" {
  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = var.display_name
  freeform_tags  = var.freeform_tags

  # Route OCI service traffic (object storage, etc.) through the Service Gateway.
  route_rules {
    destination       = var.service_cidr_block
    destination_type  = "SERVICE_CIDR_BLOCK"
    network_entity_id = var.service_gateway_id
  }

  # Route on-prem / peered networks through the DRG.
  dynamic "route_rules" {
    for_each = toset(var.drg_route_cidrs)
    content {
      destination       = route_rules.value
      destination_type  = "CIDR_BLOCK"
      network_entity_id = var.drg_id
    }
  }
}