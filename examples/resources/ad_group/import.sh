#!/bin/bash

# Import examples for ad_group resource
# Groups can be imported using various identifier formats

# Import by Distinguished Name
terraform import ad_group.basic_security "cn=IT Security Team,ou=Security Groups,dc=example,dc=com"

# Import by GUID (ObjectGUID)
terraform import ad_group.marketing_list "12345678-1234-5678-9012-123456789012"

# Import by SID
terraform import ad_group.local_access "S-1-5-21-123456789-123456789-123456789-1001"

# Import by SAM Account Name
terraform import ad_group.basic_security "ITSecurity"