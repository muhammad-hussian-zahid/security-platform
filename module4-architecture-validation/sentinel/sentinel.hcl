# ================================================
# Sentinel Configuration
# Author: Hussain
# Purpose: Define policies and enforcement levels
# ================================================

# advisory    = runs but never blocks (just warns)
# soft-mandatory = blocks but can be overridden
# hard-mandatory = always blocks, no override possible

policy "s3-security" {
  source            = "./policies/s3-security.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "encryption" {
  source            = "./policies/encryption.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "network-security" {
  source            = "./policies/network-security.sentinel"
  enforcement_level = "hard-mandatory"
}
