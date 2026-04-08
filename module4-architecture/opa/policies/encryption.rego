# ================================================
# OPA Policy: Encryption Requirements
# Author: Hussain
# Standard: GDPR Article 32, PCI-DSS Req 3,
#           ISO27001 A.10.1
# Purpose: Enforce encryption on all storage
#          resources before deployment
# ================================================

package aws.encryption

import rego.v1

# RULE 1: EBS volumes must be encrypted
# EBS = Elastic Block Storage = hard drives for AWS servers
deny contains msg if {
    resource := input.resource.aws_ebs_volume[name]
    not resource.encrypted == true
    msg := sprintf("BLOCKED: EBS volume '%v' is not encrypted. Violates GDPR Article 32 and PCI-DSS Req 3", [name])
}

# RULE 2: RDS databases must be encrypted
# RDS = Relational Database Service = managed databases in AWS
deny contains msg if {
    resource := input.resource.aws_db_instance[name]
    not resource.storage_encrypted == true
    msg := sprintf("BLOCKED: RDS database '%v' storage is not encrypted. Violates GDPR Article 32 and ISO27001 A.10.1", [name])
}

# RULE 3: S3 buckets must have server side encryption
deny contains msg if {
    resource := input.resource.aws_s3_bucket[name]
    not resource.server_side_encryption_configuration
    msg := sprintf("BLOCKED: S3 bucket '%v' has no server-side encryption. Violates PCI-DSS Req 3 and GDPR Article 32", [name])
}
