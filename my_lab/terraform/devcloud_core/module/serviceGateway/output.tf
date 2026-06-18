output "service_gateway_ocid" {
  description = "OCID of the Service Gateway."
  value       = oci_core_service_gateway.this.id
}

output "service_gateway_services" {
  description = "List of OCI service CIDR labels reachable through the Service Gateway."
  value       = data.oci_core_services.all_oci_services.services[*].cidr_block
}