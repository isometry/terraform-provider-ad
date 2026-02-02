# Import by objectGUID
terraform import ad_user.example "550e8400-e29b-41d4-a716-446655440000"

# Import by Distinguished Name
terraform import ad_user.example "CN=John Doe,OU=Users,DC=example,DC=com"

# Import by UPN
terraform import ad_user.example "john.doe@example.com"

# Import by SAM account name
terraform import ad_user.example "jdoe"

# Import by SID
terraform import ad_user.example "S-1-5-21-123456789-123456789-123456789-1001"
