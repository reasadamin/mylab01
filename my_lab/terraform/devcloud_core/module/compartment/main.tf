resource "oci_identity_compartment" "database-dev" {
  compartment_id = var.root_compartment_id
  description = "DevCloud DBA Compartment"
  name = "database-dev"
  freeform_tags = {"Team"= "DBA"}
}