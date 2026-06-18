output "nsg_ids" {
  description = "Map of NSG display name => OCID."
  value       = { for name, nsg in oci_core_network_security_group.this : name => nsg.id }
}