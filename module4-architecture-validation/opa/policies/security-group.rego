# ================================================
# OPA Policy: Security Group Controls
# Author: Hussain
# Standard: CIS AWS Benchmark, PCI-DSS Req 1
# Purpose: Block insecure network configurations
#          before deployment
# ================================================

package aws.security.network

import rego.v1

# RULE 1: Block SSH open to entire internet
deny contains msg if {
    resource := input.resource.aws_security_group[name]
    ingress := resource.ingress[_]
    ingress.from_port <= 22
    ingress.to_port >= 22
    ingress.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("BLOCKED: Security group '%v' allows SSH (port 22) from anywhere. Violates CIS AWS 4.1 and PCI-DSS Req 1", [name])
}

# RULE 2: Block ALL ports open to entire internet
deny contains msg if {
    resource := input.resource.aws_security_group[name]
    ingress := resource.ingress[_]
    ingress.from_port == 0
    ingress.to_port == 0
    ingress.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("BLOCKED: Security group '%v' allows ALL traffic from anywhere. This is a critical security violation.", [name])
}

# RULE 3: Block RDP open to entire internet
deny contains msg if {
    resource := input.resource.aws_security_group[name]
    ingress := resource.ingress[_]
    ingress.from_port <= 3389
    ingress.to_port >= 3389
    ingress.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("BLOCKED: Security group '%v' allows RDP (port 3389) from anywhere. Violates CIS AWS 4.2", [name])
}
