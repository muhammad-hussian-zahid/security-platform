# ================================================
# OPA Policy: S3 Security Controls
# Author: Hussain
# Standard: CIS AWS Benchmark, GDPR Article 32
# Purpose: Block insecure S3 configurations
#          before deployment
# ================================================

package aws.s3.security

import rego.v1

# RULE 1: Deny public S3 buckets
deny contains msg if {
    resource := input.resource.aws_s3_bucket[name]
    resource.acl == "public-read"
    msg := sprintf("BLOCKED: S3 bucket '%v' has public-read ACL. Violates GDPR Article 32 and CIS AWS 2.1.5", [name])
}

# RULE 2: Deny public-read-write buckets
deny contains msg if {
    resource := input.resource.aws_s3_bucket[name]
    resource.acl == "public-read-write"
    msg := sprintf("BLOCKED: S3 bucket '%v' has public-read-write ACL. Critical security violation.", [name])
}

# RULE 3: Require versioning on S3 buckets
deny contains msg if {
    resource := input.resource.aws_s3_bucket[name]
    versioning := resource.versioning
    not any_versioning_enabled(versioning)
    msg := sprintf("BLOCKED: S3 bucket '%v' does not have versioning enabled. Required by ISO27001 A.12.3", [name])
}

any_versioning_enabled(versioning) if {
    v := versioning[_]
    v.enabled == true
}
