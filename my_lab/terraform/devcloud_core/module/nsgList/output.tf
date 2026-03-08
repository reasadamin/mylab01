output "oci_yum_nsg_ocid" {
  value = oci_core_network_security_group.oci_yum_nsg.id
}

output "mail01_omd_nsg_ocid" {
  value = oci_core_network_security_group.mail01_omd_nsg.id
}

output "proxy01_omd_nsg_ocid" {
  value = oci_core_network_security_group.proxy01_omd_nsg.id
}

output "mgmt_omd_nsg_ocid" {
  value = oci_core_network_security_group.mgmt_omd_nsg.id
}