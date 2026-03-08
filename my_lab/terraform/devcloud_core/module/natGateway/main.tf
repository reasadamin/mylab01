resource "oci_core_nat_gateway" "vcn_nat_gw" {
    compartment_id = var.compartment_id
    vcn_id = var.vcn_id
    display_name = "vcn_nat_gw"
    #public_ip_id = oci_core_public_ip.test_public_ip.id
    route_table_id = var.route_table_id
}