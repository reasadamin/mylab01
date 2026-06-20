output "subnet_ids" {
  description = "Map of subnet display name => OCID."
  value       = { for name, s in oci_core_subnet.this : name => s.id }
}

output "subnet_cidrs" {
  description = "Map of subnet display name => CIDR block."
  value       = { for name, s in oci_core_subnet.this : name => s.cidr_block }
}