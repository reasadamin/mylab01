# Authentication is sourced from the OCI CLI config file (~/.oci/config) by
# default, so no credentials live in this repository. Pick the profile with
# var.oci_profile and override the region with var.region as needed.
provider "oci" {
  config_file_profile = var.oci_profile
  region              = var.region
}

# Alternative: direct API-key auth via variables. Supply values through
# TF_VAR_* environment variables or a gitignored *.auto.tfvars file.
# NEVER commit key material or a populated terraform.tfvars.
#
# provider "oci" {
#   tenancy_ocid     = var.tenancy_ocid
#   user_ocid        = var.user_ocid
#   private_key_path = var.private_key_path
#   fingerprint      = var.fingerprint
#   region           = var.region
# }