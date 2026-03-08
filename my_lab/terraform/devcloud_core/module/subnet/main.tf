resource "oci_core_subnet" "dbdev-a" {
  cidr_block = "10.242.8.0/24"
  compartment_id =  var.compartment_id
  vcn_id = var.vcn_id
  display_name = "dbdev-a"
  route_table_id = var.route_table_id
  prohibit_public_ip_on_vnic = true
  #security_list_ids =  
}

resource "oci_core_subnet" "dbdev-b" {
  cidr_block = "10.242.9.0/24"
  compartment_id =  var.compartment_id
  vcn_id = var.vcn_id
  display_name = "dbdev-b"
  route_table_id = var.route_table_id
  prohibit_public_ip_on_vnic = true
  #security_list_ids =  
}

resource "oci_core_subnet" "dbdev-c" {
  cidr_block = "10.242.10.0/24"
  compartment_id =  var.compartment_id
  vcn_id = var.vcn_id
  display_name = "dbdev-c"
  route_table_id = var.route_table_id
  prohibit_public_ip_on_vnic = true
  #security_list_ids =  
}