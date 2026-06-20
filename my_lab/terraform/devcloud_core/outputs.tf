output "compartment_id" {
  description = "OCID of the created compartment."
  value       = module.compartment.compartment_id
}

output "vcn_id" {
  description = "OCID of the VCN."
  value       = module.vcn.dbdev_vcn_ocid
}

output "subnet_ids" {
  description = "Map of subnet display name => OCID."
  value       = module.subnet.subnet_ids
}

output "nsg_ids" {
  description = "Map of NSG display name => OCID."
  value       = module.nsgList.nsg_ids
}

output "route_table_id" {
  description = "OCID of the route table."
  value       = module.routeTable.route_table_ocid
}

output "service_gateway_id" {
  description = "OCID of the Service Gateway."
  value       = module.serviceGateway.service_gateway_ocid
}

output "nat_gateway_public_ip" {
  description = "Public egress IP of the NAT gateway."
  value       = module.natGateway.nat_gw_public_ip
}