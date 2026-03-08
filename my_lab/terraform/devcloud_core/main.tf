module "compartment" {
  source = "./module/compartment"
  root_compartment_id = var.tenancy_ocid
}

module "vcn" {
  source = "./module/vcn"
  tenancy_ocid = var.tenancy_ocid
  compartment_id = module.compartment.database_dev_compartment_ocid
}

module "nsgList" {
  source = "./module/nsgList"
  compartment_id = module.compartment.database_dev_compartment_ocid
  vcn_id = module.vcn.dbdev_vcn_ocid
}

module "serviceGateway" {
  source = "./module/serviceGateway"
  compartment_id = module.compartment.database_dev_compartment_ocid //get the value from module
  vcn_id = module.vcn.dbdev_vcn_ocid //get the value from module
  #route_table_id = module.routeTable.default_rt_ocid  //get the value from module
}

module "routeTable" {
  source = "./module/routeTable"
  compartment_id = module.compartment.database_dev_compartment_ocid
  vcn_id = module.vcn.dbdev_vcn_ocid
  drg_ocid = var.drg_ocid
  #nat_gateway_ocid = module.gateway.nat_gw_ocid
  service_gateway_ocid = module.serviceGateway.service_gateway_ocid
}

module "subnet" {
  source = "./module/subnet"
  compartment_id = module.compartment.database_dev_compartment_ocid
  vcn_id = module.vcn.dbdev_vcn_ocid
  route_table_id = module.routeTable.default_rt_ocid
}

module "groupPolicy" {
  source = "./module/groupPolicy"
  compartment_id = module.compartment.database_dev_compartment_ocid
  dba_group_ocid = var.dba_group_ocid
  compartment_name = module.compartment.compartment_name
}
/*
module "nsgRules" {
  source = "./module/nsgRules"
  compartment_id = module.compartment.database_dev_compartment_ocid
  vcn_id = module.vcn.dbdev_vcn_ocid
  depends_on = [ module.nsgList ]
}
*/