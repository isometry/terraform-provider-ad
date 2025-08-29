# Build Hierarchy Function Examples

terraform {
  required_providers {
    ad = {
      source = "isometry/ad"
    }
  }
}

provider "ad" {
  domain   = "example.com"
  username = "admin@example.com"
  password = "secure_password"
}

# Basic organizational hierarchy
locals {
  departments = {
    "it" = {
      name = "IT Department"
    }
    "hr" = {
      name = "HR Department"
    }
    "dev-team" = {
      name   = "Development Team"
      parent = "it"
    }
    "ops-team" = {
      name   = "Operations Team"
      parent = "it"
    }
    "recruiting" = {
      name   = "Recruiting"
      parent = "hr"
    }
  }

  # Build hierarchy with default settings
  org_hierarchy = provider::ad::build_hierarchy(local.departments, {})
}

# Advanced example with custom field names
locals {
  projects = {
    "project-a" = {
      title   = "Project Alpha"
      manager = "john.doe"
    }
    "project-b" = {
      title   = "Project Beta"
      manager = "jane.smith"
    }
    "task-1" = {
      title      = "Database Design"
      reports_to = "project-a"
    }
    "task-2" = {
      title      = "API Development"
      reports_to = "project-a"
    }
    "task-3" = {
      title      = "Testing"
      reports_to = "project-b"
    }
  }

  # Custom configuration with different field names
  project_hierarchy = provider::ad::build_hierarchy(local.projects, {
    parent_field   = "reports_to"
    children_field = "tasks"
    max_depth      = 3
  })
}

# Expected result structure for org_hierarchy:
# {
#   "it" = {
#     name = "IT Department"
#     children = [
#       {
#         name = "Development Team"
#         parent = "it"
#       },
#       {
#         name = "Operations Team"
#         parent = "it"
#       }
#     ]
#   }
#   "hr" = {
#     name = "HR Department"
#     children = [
#       {
#         name = "Recruiting"
#         parent = "hr"
#       }
#     ]
#   }
#   "dev-team" = {
#     name = "Development Team"
#     parent = "it"
#   }
#   "ops-team" = {
#     name = "Operations Team"
#     parent = "it"
#   }
#   "recruiting" = {
#     name = "Recruiting"
#     parent = "hr"
#   }
# }

# Expected result structure for project_hierarchy:
# {
#   "project-a" = {
#     title = "Project Alpha"
#     manager = "john.doe"
#     tasks = [
#       {
#         title = "Database Design"
#         reports_to = "project-a"
#       },
#       {
#         title = "API Development"
#         reports_to = "project-a"
#       }
#     ]
#   }
#   "project-b" = {
#     title = "Project Beta"
#     manager = "jane.smith"
#     tasks = [
#       {
#         title = "Testing"
#         reports_to = "project-b"
#       }
#     ]
#   }
#   "task-1" = {
#     title = "Database Design"
#     reports_to = "project-a"
#   }
#   "task-2" = {
#     title = "API Development"
#     reports_to = "project-a"
#   }
#   "task-3" = {
#     title = "Testing"
#     reports_to = "project-b"
#   }
# }

# Output the hierarchical structures
output "organization" {
  value = local.org_hierarchy
}

output "projects" {
  value = local.project_hierarchy
}