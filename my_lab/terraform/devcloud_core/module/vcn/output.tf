output "dbdev_vcn_ocid" {
  description = "OCID of the VCN."
  value       = oci_core_vcn.dbdev_vcn.id
}

output "dbdev_vcn_cidr" {
  description = "Primary CIDR block of the VCN."
  value       = oci_core_vcn.dbdev_vcn.cidr_block
}

output "dbdev_vcn_cidr_blocks" {
  description = "All CIDR blocks assigned to the VCN."
  value       = oci_core_vcn.dbdev_vcn.cidr_blocks
}

output "dbdev_vcn_display_name" {
  description = "Display name of the VCN."
  value       = oci_core_vcn.dbdev_vcn.display_name
}