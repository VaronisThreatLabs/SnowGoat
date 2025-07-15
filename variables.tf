locals {
  users  = concat(jsondecode(file("${path.module}/input/users.json")))
  populate_table_users = file("${path.module}/input/tables/populate_users.sql")
  glacier_payments_table = file("${path.module}/input/tables/glacier_payments.sql")
  coldstream_users_table = file("${path.module}/input/tables/coldstream_users.sql")
  icecrew_hr_log_table = file("${path.module}/input/tables/icecrew_hr_log.sql")
  icebox_inventory_table = file("${path.module}/input/tables/icebox_inventory.sql")
  blizzard_security_table = file("${path.module}/input/tables/blizzard_security.sql")
  glacier_role_access_table = file("${path.module}/input/tables/glacier_role_access.sql")
  snow_api_tokens_table = file("${path.module}/input/tables/snow_api_tokens.sql")
  polar_crypt_vault_table = file("${path.module}/input/tables/polar_crypt_vault.sql")
  vendor_iceport_table = file("${path.module}/input/tables/vendor_iceport_table.sql")
  icebound_compliance_table = file("${path.module}/input/tables/icebound_compliance.sql")
  prod_int_acc_logs_table = file("${path.module}/input/tables/prod_int_acc_logs.sql")
}

variable "snowflake_preview_features" {
  type = list(string)
  default = ["snowflake_sequence_resource", "snowflake_table_resource", "snowflake_authentication_policy_resource", "snowflake_user_authentication_policy_attachment_resource", "snowflake_network_rule_resource", "snowflake_network_policy_attachment_resource", "snowflake_storage_integration_resource", "snowflake_stage_resource", "snowflake_table_column_masking_policy_application_resource", "snowflake_procedure_sql_resource"]
}

variable "snowflake_default_warehouse" {
  type = string
  default = "COMPUTE_WH"
}

variable "password" {
  type = string
  description = "Snowflake password"
}
