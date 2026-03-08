variable "compartment_id" {
  description = "Compartment OCID of database-dev"
  type = string
}

variable "vcn_id" {
  description = "VCN OCID of dbdev_vcn"
  type = string
}

variable "route_table_id" {
  description = "OCID of default_rt"
  type = string
}