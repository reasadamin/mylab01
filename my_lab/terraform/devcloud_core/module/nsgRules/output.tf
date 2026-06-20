output "nsg_rule_ids" {
  description = "Map of rule key => security rule OCID."
  value       = { for key, rule in oci_core_network_security_group_security_rule.this : key => rule.id }
}