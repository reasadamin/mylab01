data "oci_core_network_security_groups" "existing_nsgs" {
  compartment_id = var.compartment_id
}

locals {
  nsg_tag_map = {
    for nsg in data.oci_core_network_security_groups.existing_nsgs.network_security_groups :
    nsg.display_name => nsg.id
  }
}

resource "oci_core_network_security_group_security_rule" "oci_yum_nsg_rules" {
    for_each = var.oci_yum_nsg
    
    network_security_group_id   = tostring(lookup(local.nsg_tag_map, each.key, null))
    description                 = join(",", each.value.description)
    direction                   = each.value.direction
    protocol                    = each.value.protocol
    destination                 = each.value.destination
    destination_type            = each.value.destination_type
    
    tcp_options {
      destination_port_range {
        max                     = each.value.tcp_options.destination_port_range.max
        min                     = each.value.tcp_options.destination_port_range.min
      }
    }

}

resource "oci_core_network_security_group_security_rule" "mail01_omd_nsg_rules" {
    for_each = var.oci_mail_nsg
    
    network_security_group_id   = tostring(lookup(local.nsg_tag_map, each.key, null))
    description                 = join(",", each.value.description)
    direction                   = each.value.direction
    protocol                    = each.value.protocol
    destination                 = each.value.destination
    destination_type            = each.value.destination_type

    tcp_options {
      destination_port_range {
        max                     = each.value.tcp_options.destination_port_range.max
        min                     = each.value.tcp_options.destination_port_range.min
      }
    }
  
}

resource "oci_core_network_security_group_security_rule" "proxy_omd_nsg_rules" {
    for_each = var.oci_proxy_nsg
    
    network_security_group_id   = tostring(lookup(local.nsg_tag_map, each.key, null))
    description                 = join(",", each.value.description)
    direction                   = each.value.direction
    protocol                    = each.value.protocol
    destination                 = each.value.destination
    destination_type            = each.value.destination_type
    
    tcp_options {
      destination_port_range {
        max                     = each.value.tcp_options.destination_port_range.max
        min                     = each.value.tcp_options.destination_port_range.min
      }
    } 
  
}

resource "oci_core_network_security_group_security_rule" "mgmt_omd_nsg_rules" {
    for_each = var.oci_mgmt_nsg
    
    network_security_group_id   = tostring(lookup(local.nsg_tag_map, each.key, null))
    description                 = join(",", each.value.description)
    direction                   = each.value.direction
    protocol                    = each.value.protocol
    destination                 = each.value.destination
    destination_type            = each.value.destination_type
     
    tcp_options {
      destination_port_range {
        max                     = each.value.tcp_options.destination_port_range.max
        min                     = each.value.tcp_options.destination_port_range.min
      }
    }
}
