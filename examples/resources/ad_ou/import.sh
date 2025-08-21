#!/bin/bash

# Import examples for ad_ou resource
# OUs can be imported using various identifier formats

# Import by Distinguished Name
terraform import ad_ou.departments "ou=Departments,dc=example,dc=com"

# Import by GUID (ObjectGUID)
terraform import ad_ou.it_department "12345678-1234-5678-9012-123456789012"

# Import by SID
terraform import ad_ou.critical_systems "S-1-5-21-123456789-123456789-123456789-1001"