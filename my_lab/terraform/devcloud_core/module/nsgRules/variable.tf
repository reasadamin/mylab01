variable "vcn_id" {
  type = string
}
variable "compartment_id" {
  type = string
}

variable "oci_yum_nsg" {
  type = map(object({
    description = list(string)
    direction = optional(string)
    protocol = optional(any)
    destination = optional(string)
    destination_type = optional(string)
    tcp_options = object({
      destination_port_range = object({
        max = optional(any)
        min = optional(any)
      }) 
    })
  }))
  default = {
    "one" = { 
      description = ["Test", " NSG", " Rule", " Attachment"]
      direction = "EGRESS"
      protocol = 6
      destination  = "Service"
      destination_type = "all-bom-services-in-oracle-services-network"
      tcp_options = {
        destination_port_range = {
          max = 443
          min = 443
        }
      }
    }
    "two" = { 
      description = ["Test", "NSG", "Rule", "Attachment"]
      direction = "EGRESS"
      protocol = 6
      destination = "Service"
      destination_type = "all-bom-services-in-oracle-services-network"
      tcp_options = {
        destination_port_range = {
          max = 80
          min = 80
        }
      }
    }
  }
}

variable "oci_mail_nsg" {
  type = map(object({
    description = list(string)
    direction = string
    protocol = number
    destination = string
    destination_type = string
    tcp_options = object({
      destination_port_range = object({
        max = number
        min = number
      }) 
    })
  }))
  default = {
    "one" = {
      description = ["Test", "NSG", "Rule", "Attachment"]
      direction = "EGRESS"
      protocol = 6
      destination  = "192.168.10.50/24" 
      destination_type = "CIDR_BLOCK"
      tcp_options = {
        destination_port_range = {
          max = 443
          min = 443
        }
      }
    }
    "two" = {
      description = ["Test", "NSG", "Rule", "Attachment"]
      direction = "EGRESS"
      protocol = 6
      destination = "192.168.10.50/24"
      destination_type = "CIDR_BLOCK"
      tcp_options = {
        destination_port_range = {
          max = 80
          min = 80
        }
      }
    }
  }
}

variable "oci_proxy_nsg" {
  type = map(object({
    description = list(string)
    direction = string
    protocol = number
    destination = string
    destination_type = string
    tcp_options = object({
      destination_port_range = object({
        max = number
        min = number
      }) 
    })
  }))
  default = {
    "one" = {
      description = ["Test", "NSG", "Rule", "Attachment"]
      direction = "EGRESS"
      protocol = 6
      destination  = "CIDR_BLOCK"
      destination_type = "192.168.10.50/24"
      tcp_options = {
        destination_port_range = {
          max = 443
          min = 443
        }
      }
    }
    "two" = {
      description = ["Test", "NSG", "Rule", "Attachment"]
      direction = "EGRESS"
      protocol = 6
      destination = "CIDR_BLOCK"
      destination_type = "192.168.20.50/24"
      tcp_options = {
        destination_port_range = {
          max = 80
          min = 80
        }
      }
    }
  }
}

variable "oci_mgmt_nsg" {
  type = map(object({
    description = list(string)
    direction = string
    protocol = number
    destination = string
    destination_type = string
    tcp_options = object({
      destination_port_range = object({
        max = number
        min = number
      }) 
    })
  }))
  default = {
    "one" = {
      description = ["Test", "NSG", "Rule", "Attachment"]
      direction = "EGRESS"
      protocol = 6
      destination  = "CIDR_BLOCK"
      destination_type = "192.168.10.50/24"
      tcp_options = {
        destination_port_range = {
          max = 443
          min = 443
        }
      }
    }
    "two" = {
      description = ["Test", "NSG", "Rule", "Attachment"]
      direction = "EGRESS"
      protocol = 6
      destination = "CIDR_BLOCK"
      destination_type = "192.168.20.50/24"
      tcp_options = {
        destination_port_range = {
          max = 80
          min = 80
        }
      }
    }
  }
}