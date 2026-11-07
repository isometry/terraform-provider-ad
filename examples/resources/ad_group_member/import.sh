#!/bin/bash

# A group member can be imported using "<group-guid>/<member-guid>", the
# objectGUIDs of the group and of the member object.
# Every import form sets `member` to the member's objectGUID. Set `member`
# to the same GUID in the configuration (e.g. ad_user.alice.id) to avoid a
# replacement, which would remove and re-add the member.
terraform import ad_group_member.alice "12345678-1234-5678-9012-123456789012/87654321-4321-8765-2109-210987654321"
