resource "oci_core_network_security_group_security_rule" "this" {
  for_each = var.nsg_rules

  network_security_group_id = var.nsg_ids[each.value.nsg_name]
  description               = each.value.description
  direction                 = each.value.direction
  protocol                  = each.value.protocol
  source                    = each.value.direction == "INGRESS" ? each.value.remote : null
  source_type               = each.value.direction == "INGRESS" ? each.value.remote_type : null
  destination               = each.value.direction == "EGRESS" ? each.value.remote : null
  destination_type          = each.value.direction == "EGRESS" ? each.value.remote_type : null

  dynamic "tcp_options" {
    for_each = each.value.protocol == "6" && each.value.port != null ? [each.value.port] : []
    content {
      destination_port_range {
        min = tcp_options.value.min
        max = tcp_options.value.max
      }
    }
  }
}