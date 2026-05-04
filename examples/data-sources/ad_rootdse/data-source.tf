data "ad_rootdse" "this" {}

output "domain_controller" {
  value = data.ad_rootdse.this.dns_host_name
}

output "domain_dn" {
  value = data.ad_rootdse.this.default_naming_context
}

output "domain_name" {
  value = data.ad_rootdse.this.domain_name
}

output "forest_name" {
  value = data.ad_rootdse.this.forest.name
}

output "upn_suffixes" {
  value = data.ad_rootdse.this.forest.all_upn_suffixes
}
