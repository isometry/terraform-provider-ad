# Basic user with minimal attributes
resource "ad_user" "basic" {
  name           = "jdoe"
  principal_name = "jdoe@example.com"
  container      = "OU=Users,DC=example,DC=com"
}

# User with password and all common attributes
resource "ad_user" "full" {
  name             = "john.doe"
  principal_name   = "john.doe@example.com"
  sam_account_name = "jdoe"
  container        = "OU=Employees,OU=Users,DC=example,DC=com"

  # Password (write-only)
  # Set only on create when password_version is 0 (default)
  # Increment password_version to trigger password reset
  password = var.user_password
  # password_version = 1  # Uncomment and increment to reset password

  # Security settings
  enabled                  = true
  password_never_expires   = false
  change_password_at_logon = true

  # Personal information
  display_name = "John Doe"
  given_name   = "John"
  surname      = "Doe"
  initials     = "J"
  description  = "Software Engineer"

  # Contact information
  email_address = "john.doe@example.com"
  office_phone  = "+1-555-0100"
  mobile_phone  = "+1-555-0101"

  # Address
  street_address = "123 Main Street"
  city           = "San Francisco"
  state          = "CA"
  postal_code    = "94102"
  country        = "USA"

  # Organizational information
  title      = "Software Engineer"
  department = "Engineering"
  company    = "Example Corp"
  manager    = ad_user.manager.dn
}

# Service account
resource "ad_user" "service_account" {
  name             = "svc-app"
  principal_name   = "svc-app@example.com"
  sam_account_name = "svc-app"
  container        = "OU=Service Accounts,DC=example,DC=com"

  display_name = "Application Service Account"
  description  = "Service account for the application"

  # Typical service account settings
  enabled                = true
  password_never_expires = true
}
