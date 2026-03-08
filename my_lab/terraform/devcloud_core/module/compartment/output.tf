output "database_dev_compartment_ocid" {
  value = oci_identity_compartment.database-dev.id
}

output "compartment_name" {
  value = oci_identity_compartment.database-dev.name
}