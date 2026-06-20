output "nat_gw_ocid" {
  description = "OCID of the NAT gateway."
  value       = oci_core_nat_gateway.this.id
}

output "nat_gw_public_ip" {
  description = "Public IP address assigned to the NAT gateway."
  value       = oci_core_nat_gateway.this.nat_ip
}