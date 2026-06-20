output "policy_ocid" {
  description = "OCID of the IAM policy."
  value       = oci_identity_policy.this.id
}