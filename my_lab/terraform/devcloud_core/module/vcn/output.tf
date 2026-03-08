output "dbdev_vcn_ocid" {
  value = oci_core_vcn.dbdev_vcn.id
}

output "dbdev_vcn_cidr" {
  value = oci_core_vcn.dbdev_vcn.cidr_block
}

output "dbdev_vcn_display_name" {
  value = oci_core_vcn.dbdev_vcn.display_name
}