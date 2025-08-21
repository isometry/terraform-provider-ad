#!/bin/bash

# Import examples for ad_group_membership resource
# Group memberships can be imported using the group's identifier

# Import by group Distinguished Name
terraform import ad_group_membership.project_team_members "cn=Project Alpha Team,ou=Project Groups,dc=example,dc=com"

# Import by group GUID (ObjectGUID)
terraform import ad_group_membership.add_to_existing "12345678-1234-5678-9012-123456789012"

# Import by group SID
terraform import ad_group_membership.admin_group_members "S-1-5-21-123456789-123456789-123456789-1001"

# Import by group SAM Account Name
terraform import ad_group_membership.project_team_members "ProjectAlpha"