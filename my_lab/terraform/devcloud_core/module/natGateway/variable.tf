//Value will come from module_main
variable "compartment_id" {
  description = "Compartment OCID"
  type = string
}
//Value will come from module_main
variable "vcn_id" {
  description = "VCN OCID"
  type = string
}
//Value will come from module_main
variable "route_table_id" {
  description = "Route table OCID"
  type = string
}