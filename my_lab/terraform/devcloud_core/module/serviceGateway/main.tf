data "oci_core_services" "all_oci_services" {
  filter {
    name   = "name"
    values = ["All .* Services In Oracle Services Network"]
    regex  = true
  }
  count = 1
}

resource "oci_core_service_gateway" "vcn_svc_gw" {
  compartment_id = var.compartment_id
  vcn_id = var.vcn_id
  #route_table_id = var.route_table_id
  display_name = "vcn_svc_gw"
  services {
    #service_id = "all-bom-services-in-oracle-services-network"
    service_id = data.oci_core_services.all_oci_services[0].services.0.id
     }

}
/*

resource "oci_core_internet_gateway" "vcn_igw" {
    compartment_id = var.compartment_id
    vcn_id = var.vcn_id
    enabled = "false"
    display_name = "vcn_igw"
    route_table_id = var.route_table_id
}
*/