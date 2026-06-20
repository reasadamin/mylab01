module "compartment" {
  source              = "./module/compartment"
  root_compartment_id = var.tenancy_ocid
}

module "vcn" {
  source         = "./module/vcn"
  compartment_id = module.compartment.compartment_id
}

module "nsgList" {
  source         = "./module/nsgList"
  compartment_id = module.compartment.compartment_id
  vcn_id         = module.vcn.dbdev_vcn_ocid
}

module "serviceGateway" {
  source         = "./module/serviceGateway"
  compartment_id = module.compartment.compartment_id
  vcn_id         = module.vcn.dbdev_vcn_ocid
}

module "natGateway" {
  source         = "./module/natGateway"
  compartment_id = module.compartment.compartment_id
  vcn_id         = module.vcn.dbdev_vcn_ocid
}

module "routeTable" {
  source             = "./module/routeTable"
  compartment_id     = module.compartment.compartment_id
  vcn_id             = module.vcn.dbdev_vcn_ocid
  service_gateway_id = module.serviceGateway.service_gateway_ocid
  service_cidr_block = module.serviceGateway.service_cidr_block
  drg_id             = var.drg_ocid

  # Wire the NAT gateway to enable internet egress (0.0.0.0/0 -> NAT).
  # Set to null to keep the stricter "no internet egress" posture.
  nat_gateway_id = module.natGateway.nat_gw_ocid
}

module "subnet" {
  source         = "./module/subnet"
  compartment_id = module.compartment.compartment_id
  vcn_id         = module.vcn.dbdev_vcn_ocid
  vcn_cidr       = module.vcn.dbdev_vcn_cidr
  route_table_id = module.routeTable.route_table_ocid
}

module "groupPolicy" {
  source           = "./module/groupPolicy"
  compartment_id   = module.compartment.compartment_id
  compartment_name = module.compartment.compartment_name
  dba_group_ocid   = var.dba_group_ocid
}

module "nsgRules" {
  source  = "./module/nsgRules"
  nsg_ids = module.nsgList.nsg_ids
}