resource "oci_core_route_table" "default_rt" {
  compartment_id = var.compartment_id //get the value from module_main
  vcn_id = var.vcn_id //get the value from module_main
  display_name = "default_rt"

  route_rules {
    network_entity_id = var.drg_ocid //get the value from main_terraform_tfvar
    description =  "Route to BD VPN Network"
    destination = "10.11.0.0/16"
    destination_type =  "CIDR_BLOCK"
    route_type =  "STATIC" 
  }
  route_rules {
    network_entity_id = var.drg_ocid
    description = "Route to BD Office Network"
    destination = "192.168.0.0/20"
    destination_type = "CIDR_BLOCK"
    route_type = "STATIC"
    
  }
  route_rules {
    network_entity_id = var.drg_ocid
    description = "Route to BD Server Network"
    destination = "192.168.48.0/20"
    destination_type = "CIDR_BLOCK"
    route_type = "STATIC"
    
  }
  route_rules {
    network_entity_id = var.drg_ocid
    description = "Route to ops-dev-vcn"
    destination = "10.242.64.0/24"
    destination_type = "CIDR_BLOCK"
    route_type = "STATIC"
    
  }

  route_rules {
    network_entity_id = var.service_gateway_ocid
    description = "Route to Service Gateway"
    destination = "all-bom-services-in-oracle-services-network"
    destination_type = "SERVICE_CIDR_BLOCK"
    #route_type = "STATIC"
    #destination = var.vcn_id
    #route_table_id = var.default_rt_ocid
  }
/*
  route_rules {
    network_entity_id = var.nat_gateway_ocid
    description = "Route to NAT Gateway"
    destination = "0.0.0.0/0"
    destination_type = "CIDR_BLOCK"
    route_type = "STATIC"
 
  }
  */
 }