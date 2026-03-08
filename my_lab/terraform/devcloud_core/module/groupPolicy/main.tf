resource "oci_identity_policy" "dba_team_policy" {
  compartment_id = var.compartment_id
  description = "DBA_compartment_policy"
  name = "DBA_compartment_policy_01"

## Need to give the compartment name manually!!!!
## Have to work on that

statements = [
    "allow group ${var.dba_group_ocid} to manage all-resources in compartment database-dev",
    "allow group ${var.dba_group_ocid} to read virtual-network-family in compartment database-dev",
]

}
