variable "compartment_id" {
  description = "Compartment OCID of database-dev"
  type = string
}
variable "vcn_id" {
  description = "VCN OCID of dbdev_vcn"
  type = string
}
variable "service_gateway_ocid" {
  description = "Service GW OCID of DevCloud"
  type = string
}
variable "drg_ocid" {
  description = "DRG OCID of DevCloud"
  type = string
}
/*

variable "nat_gateway_ocid" {
  description = "NAT GW OCID of DevCloud"
  type = string
}
variable "bd_vpn_network" {
  type = string
}
variable "bd_office_network" {
  type = string
}

variable "bd_server_network" {
  type = string
}

variable "ops_dev_vcn_network" {
  type = string
}
/*
variable "nat_gateway" {
  type = string
}
*/