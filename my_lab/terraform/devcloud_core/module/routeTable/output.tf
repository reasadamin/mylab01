output "route_table_ocid" {
  description = "OCID of the route table."
  value       = oci_core_route_table.this.id
}