variable "vcn_cidr_blocks" {
  description = "IP subnet of the VCN"
  type = list(string)
  default = ["10.242.8.0/21"]
}

variable "vcn_display_name" {
  description = "Name of the vcn "
  type = string
  default = "dbdev_vcn"
}

variable "tenancy_ocid" {
  type = string
}

variable "compartment_id" {
  type = string
}