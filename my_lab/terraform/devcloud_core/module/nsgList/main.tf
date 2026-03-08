resource "oci_core_network_security_group" "oci_yum_nsg" {
  compartment_id = var.compartment_id
  display_name = "oci_yum_nsg"
  vcn_id = var.vcn_id
  freeform_tags = {
    "name":"oci_yum_nsg"
  }

}

resource "oci_core_network_security_group" "mail01_omd_nsg" {
  compartment_id = var.compartment_id
  display_name = "mail01_omd_nsg"
  vcn_id = var.vcn_id
  freeform_tags = {
    "name":"mail01_omd_nsg"
  } 
}

resource "oci_core_network_security_group" "proxy01_omd_nsg" {
  compartment_id = var.compartment_id
  display_name = "proxy01_omd_nsg"
  vcn_id = var.vcn_id
  freeform_tags = {
    "name":"proxy01_omd_nsg"
  }
}

resource "oci_core_network_security_group" "mgmt_omd_nsg" {
  compartment_id = var.compartment_id
  display_name = "mgmt_omd_nsg"
  vcn_id = var.vcn_id
  freeform_tags = {
    "name":"mgmt_omd_nsg"
  }
}
