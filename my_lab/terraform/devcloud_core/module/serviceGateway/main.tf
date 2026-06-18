data "oci_core_services" "all_oci_services" {
  filter {
    name   = "name"
    values = ["All .* Services In Oracle Services Network"]
    regex  = true
  }
}

resource "oci_core_service_gateway" "this" {
  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = var.display_name
  freeform_tags  = var.freeform_tags

  services {
    service_id = data.oci_core_services.all_oci_services.services[0].id
  }
}