resource "oci_core_vcn" "dbdev_vcn" {
  compartment_id = var.compartment_id
  cidr_blocks = var.vcn_cidr_blocks
  display_name = var.vcn_display_name
  freeform_tags = {"Team"= "DBA"}
}

/*data "oci_identity_compartments" "database_dev_compartment_ocid" {
  compartment_id = var.tenancy_ocid
  filter {
    name = "display_name"
    values = ["database-dev"]
  }
}*/
/*
resource "oci_core_vcn" "dbdev_vcn" {
  compartment_id = data.oci_identity_compartments.database_dev_compartment_ocid.id
  cidr_blocks       = var.vcn_cidr_blocks
  display_name      = var.vcn_display_name
  freeform_tags     = {"Team"= "DBA"}
}
*/