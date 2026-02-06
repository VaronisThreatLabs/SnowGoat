### Initiation of terraform providers and environments
terraform {
  required_version = ">= 1.0.0" # Ensure that the Terraform version is 1.0.0 or higher

  required_providers {
    snowflake = {
      source = "snowflakedb/snowflake"
      version = "2.3.0"
      #version = "~> 1.0.4"
    }
    local = {
      source = "hashicorp/local"
      version = "2.5.1"
    }
    aws = {
      source = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Load IP ranges as data sources
data "local_file" "azure_cloud_public_subnets" {
  filename = "${path.module}/input/azure_ranges.json"
}

data "local_file" "aws_cloud_public_subnets" {
  filename = "${path.module}/input/aws_ranges.json"
}

## Set aws provider
provider "aws" {
  # Use environment variables to provision AWS (AWS_PROFILE / AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION)
}

## Set snowflake tf provider
provider "snowflake" {
  /*
  Use environment variables:
    SNOWFLAKE_ORGANIZATION_NAME
    SNOWFLAKE_ACCOUNT_NAME
    SNOWFLAKE_USER
  */
  password = var.password
  role = "ACCOUNTADMIN"
  preview_features_enabled = var.snowflake_preview_features
}

### Users creation
# First user
resource "snowflake_user" "user1" {
  name = "blizzard_engineer"
  display_name = "Blizzard Engineer"
  login_name = "blizzard_engineer"
  password = "Aa123456!!"
  disabled = false
}

# Rest of users programmatically
resource "snowflake_user" "auto_users" {
  for_each = { for u in local.users : u.name => u }
  name = each.value.name
  display_name = each.value.display_name
  first_name = each.value.first_name
  last_name = each.value.last_name
  password = each.value.password
  disabled = each.value.disabled
}

## Databases and Schemas creation
# Databases creation
resource "snowflake_database" "db_glacier_corp" {
  name = "GLACIER_CORP"
}

resource "snowflake_schema" "schema_snowhub_internal" {
  database = snowflake_database.db_glacier_corp.name
  name     = "SNOWHUB_INTERNAL"
}

resource "snowflake_schema" "schema_frostbyte_it" {
  database = snowflake_database.db_glacier_corp.name
  name     = "FROSTBYTE_IT"
}
  resource "snowflake_table" "table_glacier_payments" {
  database = snowflake_database.db_glacier_corp.name
  schema   = snowflake_schema.schema_snowhub_internal.name
  name     = "GLACIER_PAYMENTS"

  column {
    name = "PAYMENT_ID"
    type = "string"
  }
  column {
    name = "AMOUNT_USD"
    type = "float"
  }
  column {
    name = "PAYMENT_DATE"
    type = "date"
  }
  column {
    name = "ACCOUNT_REF"
    type = "string"
  }
}

resource "snowflake_table" "table_coldstream_users" {
  database = snowflake_database.db_glacier_corp.name
  schema   = snowflake_schema.schema_snowhub_internal.name
  name     = "COLDSTREAM_USERS"

  column {
    name = "USER_ID"
    type = "string"
  }
  column {
    name = "USERNAME"
    type = "string"
  }
  column {
    name = "CREATED_AT"
    type = "TIMESTAMP_NTZ"
  }
  column {
    name = "STATUS"
    type = "string"
  }
}

resource "snowflake_table" "table_icecrew_hr_log" {
  database = snowflake_database.db_glacier_corp.name
  schema   = snowflake_schema.schema_snowhub_internal.name
  name     = "ICECREW_HR_LOG"

  column {
    name = "EMPLOYEE_ID"
    type = "string"
  }
  column {
    name = "FULL_NAME"
    type = "string"
  }
  column {
    name = "ROLE_TITLE"
    type = "string"
  }
  column {
    name = "JOINED_DATE"
    type = "date"
  }
}

resource "snowflake_table" "table_icebox_inventory" {
  database = snowflake_database.db_glacier_corp.name
  schema   = snowflake_schema.schema_snowhub_internal.name
  name     = "ICEBOX_INVENTORY"

  column {
    name = "ITEM_ID"
    type = "string"
  }
  column {
    name = "MINERAL_TYPE"
    type = "string"
  }
  column {
    name = "QUANTITY_UNITS"
    type = "float"
  }
  column {
    name = "STORAGE_ZONE"
    type = "string"
  }
}

resource "snowflake_table" "table_blizzard_security" {
  database = snowflake_database.db_glacier_corp.name
  schema   = snowflake_schema.schema_snowhub_internal.name
  name     = "BLIZZARD_SECURITY"

  column {
    name = "EVENT_ID"
    type = "string"
  }
  column {
    name = "EVENT_TYPE"
    type = "string"
  }
  column {
    name = "TIMESTAMP"
    type = "TIMESTAMP_NTZ"
  }
  column {
    name = "SEVERITY_LEVEL"
    type = "string"
  }
}

resource "snowflake_table" "table_snow_api_tokens" {
  database = snowflake_database.db_glacier_corp.name
  schema   = snowflake_schema.schema_frostbyte_it.name
  name     = "SNOW_API_TOKENS"

  column {
    name = "API_KEY_ID"
    type = "string"
  }
  column {
    name = "ASSIGNED_TO"
    type = "string"
  }
  column {
    name = "CREATED_AT"
    type = "DATE"
  }
  column {
    name = "EXPIRATION_DATE"
    type = "DATE"
  }
}

resource "snowflake_table" "table_glacier_role_access" {
  database = snowflake_database.db_glacier_corp.name
  schema   = snowflake_schema.schema_frostbyte_it.name
  name     = "GLACIER_ROLE_ACCESS"

  column {
    name = "USER_ID"
    type = "string"
  }
  column {
    name = "ROLE_NAME"
    type = "string"
  }
  column {
    name = "RESOURCE"
    type = "string"
  }
  column {
    name = "ACCESS_LEVEL"
    type = "string"
  }
}

resource "snowflake_table" "table_polar_crypt_vault" {
  database = snowflake_database.db_glacier_corp.name
  schema   = snowflake_schema.schema_frostbyte_it.name
  name     = "POLAR_CRYPT_VAULT"

  column {
    name = "ENCRYPTION_ID"
    type = "string"
  }
  column {
    name = "DATA_SCOPE"
    type = "string"
  }
  column {
    name = "ALGORITHM_USED"
    type = "string"
  }
  column {
    name = "ENCRYPTED_AT"
    type = "TIMESTAMP_NTZ"
  }
}

resource "snowflake_table" "table_vendor_iceport" {
  database = snowflake_database.db_glacier_corp.name
  schema   = snowflake_schema.schema_frostbyte_it.name
  name     = "VENDOR_ICEPORT"

  column {
    name = "VENDOR_ID"
    type = "string"
  }
  column {
    name = "VENDOR_NAME"
    type = "string"
  }
  column {
    name = "SERVICE_TYPE"
    type = "string"
  }
  column {
    name = "ONBOARDED_AT"
    type = "date"
  }
}

resource "snowflake_table" "table_icebound_compliance" {
  database = snowflake_database.db_glacier_corp.name
  schema   = snowflake_schema.schema_frostbyte_it.name
  name     = "ICEBOUND_COMPLIANCE"

  column {
    name = "LOG_ID"
    type = "string"
  }
  column {
    name = "AUDIT_TYPE"
    type = "string"
  }
  column {
    name = "REVIEW_DATE"
    type = "date"
  }
  column {
    name = "STATUS"
    type = "string"
  }
}

resource "snowflake_table" "table_prod_int_acc_logs" {
  database = snowflake_database.db_glacier_corp.name
  schema   = snowflake_schema.schema_frostbyte_it.name
  name     = "PROD_INT_ACC_LOGS"

  column {
    name = "REQUEST_ID"
    type = "VARCHAR"
  }

  column {
    name = "DATE_UTC"
    type = "DATETIME"
  }

  column {
    name = "ORIGIN_IP"
    type = "VARCHAR"
  }

  column {
    name = "RAW_LOG"
    type = "VARCHAR"
  }

  column {
    name = "PAYLOAD"
    type = "VARCHAR"
  }
}

## Stage 1 - Access and authentication policies w/ first user
# Authentication policy - MFA Only except SNOWSQL
resource "snowflake_authentication_policy" "auth_policy_mfa_only" {
  database = snowflake_database.db_glacier_corp.name
  schema = snowflake_schema.schema_snowhub_internal.name
  name = "MFA_ONLY"
  client_types = ["SNOWSQL"]
  security_integrations = ["ALL"]
}

# Enforce authentication policy on first user
resource "snowflake_user_authentication_policy_attachment" "auth_policy_att_mfa_only" {
  authentication_policy_name = snowflake_authentication_policy.auth_policy_mfa_only.fully_qualified_name
  user_name = snowflake_user.user1.name
}

# Network rule - allow Azure only - rule creation
resource "snowflake_network_rule" "net_rule_allow_az_only" {
  name = "ALLOW_AZ_VM_ONLY"
  database = snowflake_database.db_glacier_corp.name
  schema = snowflake_schema.schema_snowhub_internal.name
  comment = "Allow ingress communication from Azure VMs."
  type = "IPV4"
  mode = "INGRESS"
  value_list = jsondecode(data.local_file.azure_cloud_public_subnets.content)["ranges"]
}

# Network rule - allow AWS only - rule creation
resource "snowflake_network_rule" "net_rule_allow_aws_only" {
  name = "ALLOW_AWS_EC2_ONLY"
  database = snowflake_database.db_glacier_corp.name
  schema = snowflake_schema.schema_snowhub_internal.name
  comment = "Allow ingress communication from AWS EC2."
  type = "IPV4"
  mode = "INGRESS"
  value_list = jsondecode(data.local_file.aws_cloud_public_subnets.content)["ranges"]
}

# Network policy use network rules
resource "snowflake_network_policy" "network_policy_allow_cloud_resources" {
  name = "ALLOW_CLOUD_RESOURCES"
  allowed_network_rule_list = [snowflake_network_rule.net_rule_allow_az_only.fully_qualified_name, snowflake_network_rule.net_rule_allow_aws_only.fully_qualified_name]
}

# Enforce network policy on first user
resource "snowflake_network_policy_attachment" "network_policy_att_allow_cloud_resources" {
  network_policy_name = snowflake_network_policy.network_policy_allow_cloud_resources.name
  set_for_account = false
  users = [snowflake_user.user1.name]
}

## Create tables
# Create sequence for USER_ID
resource "snowflake_sequence" "user_id_sequence" {
  database = snowflake_schema.schema_snowhub_internal.database
  schema = snowflake_schema.schema_snowhub_internal.name
  name = "USER_ID_SEQUENCE"
}

# Create sequence for TRANSACTION_ID
resource "snowflake_sequence" "transaction_id_sequence" {
  database = snowflake_schema.schema_snowhub_internal.database
  schema = snowflake_schema.schema_snowhub_internal.name
  name = "TRANSACTION_ID_SEQUENCE"
}

# Create USERS table
resource "snowflake_table" "table_users" {
  database = snowflake_schema.schema_snowhub_internal.database
  name = "USERS"
  schema = snowflake_schema.schema_snowhub_internal.name

  column {
    name = "USER_ID"
    type = "int"

    default {
      sequence = snowflake_sequence.user_id_sequence.fully_qualified_name
    }
  }

  column {
    name = "USERNAME"
    type = "string"
  }

  column {
    name = "SSN"
    type = "string"
  }

  column {
    name = "EMAIL"
    type = "string"
  }

  column {
    name = "PASSWORD"
    type = "string"
  }

  column {
    name = "STATE"
    type = "string"
  }
}

## Populate tables
# Populate USERS table
resource "snowflake_execute" "exec_populate_users" {
  execute = local.populate_table_users
  revert = "DELETE FROM ${snowflake_table.table_users.fully_qualified_name};"
  depends_on = [snowflake_table.table_users]
}
#
resource "snowflake_execute" "exec_populate" {
  execute = local.glacier_payments_table
  revert = "DELETE FROM GLACIER_CORP.SNOWHUB_INTERNAL.GLACIER_PAYMENTS;"
  depends_on = [snowflake_table.table_glacier_payments]
}

resource "snowflake_execute" "exec_populate_coldstream" {
  execute = local.coldstream_users_table
  revert = "DELETE FROM GLACIER_CORP.SNOWHUB_INTERNAL.COLDSTREAM_USERS;"
  depends_on = [snowflake_table.table_coldstream_users]
}

resource "snowflake_execute" "exec_populate_ice_hr_log" {
  execute = local.icecrew_hr_log_table
  revert = "DELETE FROM GLACIER_CORP.SNOWHUB_INTERNAL.ICECREW_HR_LOG;"
  depends_on = [snowflake_table.table_icecrew_hr_log]
}

resource "snowflake_execute" "exec_populate_icebox_inventory_table" {
  execute = local.icebox_inventory_table
  revert = "DELETE FROM GLACIER_CORP.SNOWHUB_INTERNAL.ICEBOX_INVENTORY;"
  depends_on = [snowflake_table.table_icebox_inventory]
}

resource "snowflake_execute" "exec_populate_blizzard_security_table_table" {
  execute = local.blizzard_security_table
  revert = "DELETE FROM GLACIER_CORP.SNOWHUB_INTERNAL.BLIZZARD_SECURITY;"
  depends_on = [snowflake_table.table_blizzard_security]
}

resource "snowflake_execute" "exec_populate_glacier_role_access_table" {
  execute = local.glacier_role_access_table
  revert = "DELETE FROM GLACIER_CORP.FROSTBYTE_IT.GLACIER_ROLE_ACCESS;"
  depends_on = [snowflake_table.table_glacier_role_access]
}

resource "snowflake_execute" "exec_populate_snow_api_tokens_table" {
  execute = local.snow_api_tokens_table
  revert = "DELETE FROM GLACIER_CORP.FROSTBYTE_IT.SNOW_API_TOKENS;"
  depends_on = [snowflake_table.table_snow_api_tokens]
}

resource "snowflake_execute" "exec_populate_polar_crypt_vault_table" {
  execute = local.polar_crypt_vault_table
  revert = "DELETE FROM GLACIER_CORP.FROSTBYTE_IT.POLAR_CRYPT_VAULT;"
  depends_on = [snowflake_table.table_polar_crypt_vault]
}

resource "snowflake_execute" "exec_populate_vendor_iceport_table" {
  execute = local.vendor_iceport_table
  revert = "DELETE FROM GLACIER_CORP.FROSTBYTE_IT.VENDOR_ICEPORT;"
  depends_on = [snowflake_table.table_vendor_iceport]
}

resource "snowflake_execute" "exec_populate_icebound_compliance_table" {
  execute = local.icebound_compliance_table
  revert = "DELETE FROM GLACIER_CORP.FROSTBYTE_IT.ICEBOUND_COMPLIANCE;"
  depends_on = [snowflake_table.table_icebound_compliance]
}

resource "snowflake_execute" "exec_populate_prod_int_acc_logs" {
  execute = local.prod_int_acc_logs_table
  revert = "DELETE FROM GLACIER_CORP.FROSTBYTE_IT.PROD_INT_ACC_LOGS;"
  depends_on = [snowflake_table.table_prod_int_acc_logs]
}

## Create external integration & stage
# Create the external AWS S3 bucket
resource "aws_s3_bucket" "s3_external_bucket" {
  tags = {
    Name = "snowgoat-external-stage-storage"
  }
}

# Upload stage files to S3 bucket
resource "aws_s3_object" "s3_upload_sensitive_files" {
  bucket = aws_s3_bucket.s3_external_bucket.id
  key = "sensitive_information/application_users_backup.csv"
  source = "${path.module}/input/application_users_backup.csv"
}

## Create IAM roles and policies for external integration
# Create IAM policy to read files from S3
resource "aws_iam_policy" "iam_policy_for_snowflake_read" {
  name = "s3_snowflake_external_integration_policy"
#  path = "/"
  description = "Policy to allow snowflake integration file load"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ],
        Resource = "${aws_s3_bucket.s3_external_bucket.arn}/sensitive_information/*"
      },
      {
        Effect = "Allow",
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ],
        Resource = aws_s3_bucket.s3_external_bucket.arn
      }
    ]
  })
}

  # Create IAM role for snowflake integration
  resource "aws_iam_role" "iam_role_snowflake_integration" {
  name = "snowflake_external_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Deny"
        Action = "sts:AssumeRole"
        Principal = {
          AWS = "*"
        }
      }
    ]
  })
}

# Attach policy to created role
resource "aws_iam_role_policy_attachment" "attach_aws_policy_to_aws_role" {
  role = aws_iam_role.iam_role_snowflake_integration.name
  policy_arn = aws_iam_policy.iam_policy_for_snowflake_read.arn
}

# To avoid a Terraform 'Cycle Error', we need to update the AWS role with the correct trusted relationship,
# using the new snowflake arns we received from the integration
resource "null_resource" "update_iam_role" {
  depends_on = [snowflake_storage_integration.integration_aws_backup, aws_iam_role.iam_role_snowflake_integration]
  triggers = {
    always_run = timestamp()
  }
  provisioner "local-exec" {
    command = <<EOT
      aws iam update-assume-role-policy --role-name ${aws_iam_role.iam_role_snowflake_integration.name} --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Principal": {
              "AWS": "${snowflake_storage_integration.integration_aws_backup.storage_aws_iam_user_arn}"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
              "StringEquals": {
                "sts:ExternalId": "${snowflake_storage_integration.integration_aws_backup.storage_aws_external_id}"
              }
            }
          }
        ]
      }'
    EOT
  }
}

# Create external integration w/ AWS S3
resource "snowflake_storage_integration" "integration_aws_backup" {
  depends_on = [aws_iam_role.iam_role_snowflake_integration]
  name = "BACKUP_LEGACY_AWS_INTEGRATION"
  comment = "Backup stage from legacy AWS env."
  type = "EXTERNAL_STAGE"
  enabled = true
  storage_allowed_locations = ["s3://${aws_s3_bucket.s3_external_bucket.bucket}/sensitive_information/"]
  storage_provider = "S3"
  storage_aws_role_arn = aws_iam_role.iam_role_snowflake_integration.arn
}

# Create a stage, using the external integration
resource "snowflake_stage" "stage_external_aws_backup" {
  name = "BACKUP_LEGACY_AWS_STAGE"
  url = "s3://${aws_s3_bucket.s3_external_bucket.bucket}/sensitive_information/"
  database = snowflake_database.db_glacier_corp.name
  schema = snowflake_schema.schema_snowhub_internal.name
  storage_integration = snowflake_storage_integration.integration_aws_backup.name
}

# Disable COPY INTO external sources
resource "snowflake_account_parameter" "account_param_disable_copyinto_external" {
  key = "PREVENT_UNLOAD_TO_INLINE_URL"
  value = "true"
}

## Procedures
resource "snowflake_procedure_sql" "procedure_get_encoded_payload" {
  database = snowflake_database.db_glacier_corp.name
  schema = snowflake_schema.schema_frostbyte_it.name
  name = "GET_ENCODED_PAYLOAD"
  arguments {
    arg_data_type = "VARCHAR(200)"
    arg_name = "REQUEST_ID"
  }
  return_type = "VARCHAR(200)"
  execute_as = "OWNER"

  procedure_definition = <<EOT
    DECLARE
        encoded_payload STRING;
    BEGIN
        SELECT PAYLOAD
        INTO encoded_payload
        FROM GLACIER_CORP.FROSTBYTE_IT.PROD_INT_ACC_LOGS
        WHERE REQUEST_ID = :REQUEST_ID;
        RETURN 'payload: ' || encoded_payload;
    END;
EOT
}

## Create Stage 1 Role and Privs
# Backup and DR role creation
resource "snowflake_account_role" "role_scenario1_backup_and_dr" {
  name = "ICE_BACKUP_OPS"
  comment = "Crevasses emergency team"
}

# Backup and DR add privilege to read the external stage
resource "snowflake_grant_privileges_to_account_role" "role_priv_scenario1_backup_and_dr-read_stage" {
  account_role_name = snowflake_account_role.role_scenario1_backup_and_dr.name
  privileges = ["READ"]
  on_schema_object {
    object_type = "STAGE"
    object_name = snowflake_stage.stage_external_aws_backup.fully_qualified_name
  }
}

# Grant backup and DR role to first user
resource "snowflake_grant_account_role" "role_grant_scenario1_backup_and_dr" {
  role_name = snowflake_account_role.role_scenario1_backup_and_dr.name
  user_name = snowflake_user.user1.name
}

# Permission to use warehouse
resource "snowflake_grant_privileges_to_account_role" "role_priv_backup_and_dr-usage_warehouse" {
  account_role_name = snowflake_account_role.role_scenario1_backup_and_dr.name
  privileges = ["USAGE"]
  on_account_object {
    object_name = var.snowflake_default_warehouse
    object_type = "WAREHOUSE"
  }
}

# Permission to use database
resource "snowflake_grant_privileges_to_account_role" "role_priv_backup_and_dr-usage_database" {
  account_role_name = snowflake_account_role.role_scenario1_backup_and_dr.name
  privileges = ["USAGE"]
  on_account_object {
    object_name = snowflake_database.db_glacier_corp.fully_qualified_name
    object_type = "DATABASE"
  }
}

# Permission to use schema
resource "snowflake_grant_privileges_to_account_role" "role_priv_backup_and_dr-usage_schema" {
  account_role_name = snowflake_account_role.role_scenario1_backup_and_dr.name
  privileges = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_snowhub_internal.fully_qualified_name
  }
}

# Grant backup and DR role to ACCOUNTADMIN for successful terraform destroy
resource "snowflake_grant_account_role" "role_grant_master_backup_and_dr" {
  role_name = snowflake_account_role.role_scenario1_backup_and_dr.name
  parent_role_name = "ACCOUNTADMIN"
}

## Stage 2 - Create masking-policy to mask SSN and payloads
# Create masking policy mask_pii
resource "snowflake_masking_policy" "masking_pii" {
  database = snowflake_schema.schema_snowhub_internal.database
  name = "MASK_PII"
  return_data_type = "VARCHAR"
  schema = snowflake_schema.schema_snowhub_internal.name
  argument {
    name = "SSN"
    type = "VARCHAR"
  }
  body =<<-EOF
  case
    when current_role() in ('ACCOUNTADMIN') then
      SSN
    else
      'PII_REDACTED'
  end
EOF
}

# Create masking-policy mask_payloads
resource "snowflake_masking_policy" "masking_payloads" {
  database = snowflake_schema.schema_frostbyte_it.database
  name = "MASK_PAYLOADS"
  return_data_type = "VARCHAR"
  schema = snowflake_schema.schema_frostbyte_it.name
  argument {
    name = "PAYLOAD"
    type = "VARCHAR"
  }
  body =<<-EOF
  case
    when current_role() in ('ACCOUNTADMIN') then
      PAYLOAD
    else
      'PAYLOAD_REDACTED'
  end
EOF
}

# Set masking-policy to SSN column
resource "snowflake_table_column_masking_policy_application" "set_masking_ssn" {
  table = snowflake_table.table_users.fully_qualified_name
  column = "SSN"
  masking_policy = snowflake_masking_policy.masking_pii.fully_qualified_name
}

# Set masking-policy to PAYLOAD column
resource "snowflake_table_column_masking_policy_application" "set_masking_payloads" {
  table = snowflake_table.table_prod_int_acc_logs.fully_qualified_name
  column = "PAYLOAD"
  masking_policy = snowflake_masking_policy.masking_payloads.fully_qualified_name
}

## Stage 2 - Devops Team Lead and account ownership takeover
# Devops TL role creation
resource "snowflake_account_role" "role_scenario1_devops_team_lead" {
  name = "GLACIAL_OPSMASTER"
  comment = "Role for DevOps teams leaders."
}

resource "snowflake_account_role" "role_ice_admin" {
  name    = "ICE_ADMIN"
  comment = "Full system administrator"
}

resource "snowflake_account_role" "role_frost_operator" {
  name    = "FROST_OPERATOR"
  comment = "Power user / can manage critical operations"
}

resource "snowflake_account_role" "role_glacier_reader" {
  name    = "GLACIER_READER"
  comment = "Read-only access to deep (archived) data"
}

resource "snowflake_account_role" "role_blizzard_writer" {
  name    = "BLIZZARD_WRITER"
  comment = "Can write/modify high-volume data"
}

resource "snowflake_account_role" "role_arctic_analyst" {
  name    = "ARCTIC_ANALYST"
  comment = "Analyst with data access but no admin rights"
}

resource "snowflake_account_role" "role_frozen_auditor" {
  name    = "FROZEN_AUDITOR"
  comment = "Read-only access for compliance/auditing"
}

resource "snowflake_account_role" "role_permafrost_dev" {
  name    = "PERMAFROST_DEV"
  comment = "Developer role — stable and limited scope"
}

resource "snowflake_account_role" "role_polar_guardian" {
  name    = "POLAR_GUARDIAN"
  comment = "Security-focused role (e.g., access control)"
}

resource "snowflake_account_role" "role_snowflake_viewer" {
  name    = "SNOWFLAKE_VIEWER"
  comment = "Basic user role — read-only, limited visibility"
}

resource "snowflake_account_role" "role_iceberg_engineer" {
  name    = "ICEBERG_ENGINEER"
  comment = "Technical maintainer for backend systems"
}

resource "snowflake_account_role" "role_artic_admin" {
  name    = "ARTIC_ADMIN"
  comment = "Reserved admin role (archival or legacy access)"
}

resource "snowflake_account_role" "role_snowstorm_engineer" {
  name    = "SNOWSTORM_ENGINEER"
  comment = "The brave storm engineers"
}

resource "snowflake_grant_account_role" "role_grant_crystal_blade_1" {
  role_name = snowflake_account_role.role_ice_admin.name
  user_name = snowflake_user.auto_users["crystal_blade"].name
}

resource "snowflake_grant_account_role" "role_grant_crystal_blade_2" {
  role_name = snowflake_account_role.role_blizzard_writer.name
  user_name = snowflake_user.auto_users["crystal_blade"].name
}

resource "snowflake_grant_account_role" "role_grant_frostwalker_1" {
  role_name = snowflake_account_role.role_snowflake_viewer.name
  user_name = snowflake_user.auto_users["frostwalker"].name
}

resource "snowflake_grant_account_role" "role_grant_glacier_glider_1" {
  role_name = snowflake_account_role.role_artic_admin.name
  user_name = snowflake_user.auto_users["glacier_glider"].name
}

resource "snowflake_grant_account_role" "role_grant_icebound_alpha_1" {
  role_name = snowflake_account_role.role_glacier_reader.name
  user_name = snowflake_user.auto_users["icebound_alpha"].name
}

resource "snowflake_grant_account_role" "role_grant_icebound_alpha_2" {
  role_name = snowflake_account_role.role_snowstorm_engineer.name
  user_name = snowflake_user.auto_users["icebound_alpha"].name
}

resource "snowflake_grant_account_role" "role_grant_arctic_shadow_1" {
  role_name = snowflake_account_role.role_frozen_auditor.name
  user_name = snowflake_user.auto_users["arctic_shadow"].name
}

resource "snowflake_grant_account_role" "role_grant_blizzard_beast_1" {
  role_name = snowflake_account_role.role_permafrost_dev.name
  user_name = snowflake_user.auto_users["blizzard_beast"].name
}

resource "snowflake_grant_account_role" "role_grant_permafrost_beta_1" {
  role_name = snowflake_account_role.role_blizzard_writer.name
  user_name = snowflake_user.auto_users["permafrost_beta"].name
}

resource "snowflake_grant_account_role" "role_grant_permafrost_beta_2" {
  role_name = snowflake_account_role.role_iceberg_engineer.name
  user_name = snowflake_user.auto_users["permafrost_beta"].name
}

resource "snowflake_grant_account_role" "role_grant_snow_drifter_1" {
  role_name = snowflake_account_role.role_polar_guardian.name
  user_name = snowflake_user.auto_users["snow_drifter"].name
}

resource "snowflake_grant_account_role" "role_grant_icy_vault_1" {
  role_name = snowflake_account_role.role_artic_admin.name
  user_name = snowflake_user.auto_users["icy_vault"].name
}

resource "snowflake_grant_account_role" "role_grant_icy_vault_2" {
  role_name = snowflake_account_role.role_ice_admin.name
  user_name = snowflake_user.auto_users["icy_vault"].name
}

resource "snowflake_grant_account_role" "role_grant_polar_pixel_1" {
  role_name = snowflake_account_role.role_snowflake_viewer.name
  user_name = snowflake_user.auto_users["polar_pixel"].name
}

resource "snowflake_grant_account_role" "role_grant_frozen_trace_1" {
  role_name = snowflake_account_role.role_frost_operator.name
  user_name = snowflake_user.auto_users["frozen_trace"].name
}

resource "snowflake_grant_account_role" "role_grant_frozen_trace_2" {
  role_name = snowflake_account_role.role_glacier_reader.name
  user_name = snowflake_user.auto_users["frozen_trace"].name
}

resource "snowflake_grant_account_role" "role_grant_chillcode_x_1" {
  role_name = snowflake_account_role.role_permafrost_dev.name
  user_name = snowflake_user.auto_users["chillcode_x"].name
}

resource "snowflake_grant_account_role" "role_grant_tundra_scout_1" {
  role_name = snowflake_account_role.role_arctic_analyst.name
  user_name = snowflake_user.auto_users["tundra_scout"].name
}

resource "snowflake_grant_account_role" "role_grant_tundra_scout_2" {
  role_name = snowflake_account_role.role_iceberg_engineer.name
  user_name = snowflake_user.auto_users["tundra_scout"].name
}

resource "snowflake_grant_account_role" "role_grant_frostbyte_9_1" {
  role_name = snowflake_account_role.role_snowstorm_engineer.name
  user_name = snowflake_user.auto_users["frostbyte_9"].name
}

resource "snowflake_grant_account_role" "role_grant_frostbyte_9_2" {
  role_name = snowflake_account_role.role_frost_operator.name
  user_name = snowflake_user.auto_users["frostbyte_9"].name
}

resource "snowflake_grant_account_role" "role_grant_glimmer_frost_1" {
  role_name = snowflake_account_role.role_artic_admin.name
  user_name = snowflake_user.auto_users["glimmer_frost"].name
}

resource "snowflake_grant_account_role" "role_grant_shiver_ops_1" {
  role_name = snowflake_account_role.role_ice_admin.name
  user_name = snowflake_user.auto_users["shiver_ops"].name
}

resource "snowflake_grant_account_role" "role_grant_iceflux_1" {
  role_name = snowflake_account_role.role_frozen_auditor.name
  user_name = snowflake_user.auto_users["iceflux"].name
}

resource "snowflake_grant_account_role" "role_grant_subzero_stack_1" {
  role_name = snowflake_account_role.role_arctic_analyst.name
  user_name = snowflake_user.auto_users["subzero_stack"].name
}

resource "snowflake_grant_account_role" "role_grant_subzero_stack_2" {
  role_name = snowflake_account_role.role_blizzard_writer.name
  user_name = snowflake_user.auto_users["subzero_stack"].name
}

# Grant devops TL ownership on two users -#lskywalker
resource "snowflake_grant_ownership" "own_scenario1_devops_team_lead_snowwarden" {
  account_role_name = snowflake_account_role.role_scenario1_devops_team_lead.name
  on {
    object_type = "USER"
    object_name = snowflake_user.auto_users["Fr0stUnv3il3d"].name
  }
}

resource "snowflake_grant_ownership" "own_scenario1_devops_team_lead_crystal_blade" {
  account_role_name = snowflake_account_role.role_scenario1_devops_team_lead.name
  on {
    object_type = "USER"
    object_name = snowflake_user.auto_users["crystal_blade"].name
  }
}

# Permissions for devops TL to use default warehouse
resource "snowflake_grant_privileges_to_account_role" "role_priv_scenario1_devops_team_lead-usage_warehouse" {
  account_role_name = snowflake_account_role.role_scenario1_devops_team_lead.name
  privileges = ["USAGE"]
  on_account_object {
    object_name = var.snowflake_default_warehouse
    object_type = "WAREHOUSE"
  }
}

# Permissions for devops TL to use schema
resource "snowflake_grant_privileges_to_account_role" "role_priv_scenario1_devops_team_lead-usage_schema" {
  account_role_name = snowflake_account_role.role_scenario1_devops_team_lead.name
  privileges = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_snowhub_internal.fully_qualified_name
  }
}

# Permission for devops TL to use db
resource "snowflake_grant_privileges_to_account_role" "role_priv_scenario1_devops_team_lead-usage_database" {
  account_role_name = snowflake_account_role.role_scenario1_devops_team_lead.name
  privileges = ["USAGE"]
  on_account_object {
    object_name = snowflake_database.db_glacier_corp.name
    object_type = "DATABASE"
  }
}

# Permission for devops TL to read users table
resource "snowflake_grant_privileges_to_account_role" "role_priv_scenario1_devops_team_lead-read_users_table" {
  account_role_name = snowflake_account_role.role_scenario1_devops_team_lead.name
  privileges = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_users.fully_qualified_name
    object_type = "TABLE"
  }
}

# Grant devops TL to a user#dvader > snowwarden
resource "snowflake_grant_account_role" "role_grant_scenario1_devops_team_lead" {
  role_name = snowflake_account_role.role_scenario1_devops_team_lead.name
  user_name = snowflake_user.auto_users["snowwarden"].name
}

# Grant devopsTL role to ACCOUNTADMIN as well, so then terraform destroy via ACCOUNTADMIN could work
resource "snowflake_grant_account_role" "role_grant_master_devops" {
  role_name = snowflake_account_role.role_scenario1_devops_team_lead.name
  parent_role_name = "ACCOUNTADMIN" # Grant this role to the ACCOUNTADMIN deployer user for future successful destroys
}

## Stage 2 - Role to unset masking policy
# Masking admin role creation
#ROLE_MASKING_ADMIN
resource "snowflake_account_role" "role_scenario1_masking_admin" {
  name = "ROLE_SNOWCLOAK_MASKER"
  comment = "Royal FrostOps team leaders"
}

# Permission for masking admin role to set/unset masking policies
resource "snowflake_grant_privileges_to_account_role" "role_priv_masking_admin-apply_masking_policy" {
  account_role_name = snowflake_account_role.role_scenario1_masking_admin.name
  privileges = ["APPLY"]
  on_schema_object {
    object_name = snowflake_masking_policy.masking_pii.fully_qualified_name
    object_type = "MASKING POLICY"
  }
}

# Permissions for masking admin to use default warehouse
resource "snowflake_grant_privileges_to_account_role" "role_priv_scenario1_masking_admin-usage_warehouse" {
  account_role_name = snowflake_account_role.role_scenario1_masking_admin.name
  privileges = ["USAGE"]
  on_account_object {
    object_name = var.snowflake_default_warehouse
    object_type = "WAREHOUSE"
  }
}

# Permission for masking admin role to use database
resource "snowflake_grant_privileges_to_account_role" "role_priv_masking_admin-usage_database" {
  account_role_name = snowflake_account_role.role_scenario1_masking_admin.name
  privileges = ["USAGE"]
  on_account_object {
    object_name = snowflake_database.db_glacier_corp.fully_qualified_name
    object_type = "DATABASE"
  }
}

# Permission for masking admin role to use schema
resource "snowflake_grant_privileges_to_account_role" "role_priv_masking_admin-usage_schema" {
  account_role_name = snowflake_account_role.role_scenario1_masking_admin.name
  privileges = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_snowhub_internal.fully_qualified_name
  }
}

# Permission for masking admin role to own table
resource "snowflake_grant_ownership" "own_scenario1_masking_admin-user_table" {
  account_role_name = snowflake_account_role.role_scenario1_masking_admin.name
  outbound_privileges = "COPY"
  on {
    object_type = "TABLE"
    object_name = snowflake_table.table_users.fully_qualified_name
  }
}

# Grant masking admin role to a Devops engineer under DevopsTL
resource "snowflake_grant_account_role" "role_grant_scenario1_masking_admin" {
  role_name = snowflake_account_role.role_scenario1_masking_admin.name
  user_name = snowflake_user.auto_users["Fr0stUnv3il3d"].name     #lskywalker
}

# Grant masking admin role to ACCOUNTADMIN as well, so then terraform destroy via ACCOUNTADMIN could work
resource "snowflake_grant_account_role" "role_grant_master_masking_admin" {
  role_name = snowflake_account_role.role_scenario1_masking_admin.name
  parent_role_name = "ACCOUNTADMIN" # Grant this role to the ACCOUNTADMIN deployer user for future successful destroys
}

## Stage X - role for reading next DB
resource "snowflake_account_role" "role_bonus_glacier_internal_contrib" {
  name = "ROLE_GLACIER_INTERNAL_CONTRIB"
  comment = "Role for general contribution for Glacier Corp internal organization data."
}

# Permission for glacier_internal_contrib role to use glacier db
resource "snowflake_grant_privileges_to_account_role" "role_priv_glacier_internal_contrib-use_glacier_db" {
  account_role_name = snowflake_account_role.role_bonus_glacier_internal_contrib.name
  privileges = ["USAGE"]
  on_account_object {
    object_name = snowflake_database.db_glacier_corp.fully_qualified_name
    object_type = "DATABASE"
  }
}

# Permission for glacier_internal_contrib role to use FROSTBYTE_IT schema
resource "snowflake_grant_privileges_to_account_role" "role_priv_glacier_internal_contrib-use_frostbyte_schema" {
  account_role_name = snowflake_account_role.role_bonus_glacier_internal_contrib.name
  privileges = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_frostbyte_it.fully_qualified_name
  }
}

# Permission for glacier_internal_contrib role to read FROSTBYTE_IT schema tables
resource "snowflake_grant_privileges_to_account_role" "role_priv_glacier_internal_contrib-read_frostbyte_schema" {
  account_role_name = snowflake_account_role.role_bonus_glacier_internal_contrib.name
  privileges = ["SELECT"]
  on_schema_object {
    all {
      object_type_plural = "TABLES"
      in_schema = snowflake_schema.schema_frostbyte_it.fully_qualified_name
    }
  }
  depends_on = [snowflake_table.table_prod_int_acc_logs, snowflake_table.table_glacier_role_access, snowflake_table.table_icebound_compliance, snowflake_table.table_polar_crypt_vault, snowflake_table.table_snow_api_tokens, snowflake_table.table_vendor_iceport]
}

# Grant glacier_internal_contrib role to a user
resource "snowflake_grant_account_role" "role_grant_glacier_internal_contrib-to_user" {
  role_name = snowflake_account_role.role_bonus_glacier_internal_contrib.name
  user_name = snowflake_user.auto_users["Fr0stUnv3il3d"].name     #lskywalker
}

resource "snowflake_grant_account_role" "role_grant_glacier_internal_contrib-to_accountadmin" {
  role_name = snowflake_account_role.role_bonus_glacier_internal_contrib.name
  parent_role_name = "ACCOUNTADMIN" # Grant this role to the ACCOUNTADMIN deployer user for future successful destroys
}

# Permission for glacier_internal_contrib role to execute procedure
resource "snowflake_grant_privileges_to_account_role" "role_priv_glacier_internal_contrib-use_procedure_glacier_corp" {
  account_role_name = snowflake_account_role.role_bonus_glacier_internal_contrib.name
  privileges = ["USAGE"]
  on_schema_object {
    object_name = snowflake_procedure_sql.procedure_get_encoded_payload.fully_qualified_name
    object_type = "PROCEDURE"
  }
  depends_on = [snowflake_procedure_sql.procedure_get_encoded_payload, snowflake_account_role.role_bonus_glacier_internal_contrib]
}

# Output first user context credentials
output "first_user" {
  value = {
    "username": snowflake_user.user1.name
    "pass": "Aa123456!!"
  }
  description = "This is the first user account to start interacting w/ your SnowGoat instance!"
}

## Noise
# Grant USAGE on GLACIER_CORP database
resource "snowflake_grant_privileges_to_account_role" "role_priv_iceberg_engineer-usage_database" {
  account_role_name = snowflake_account_role.role_iceberg_engineer.name
  privileges        = ["USAGE"]
  on_account_object {
    object_name = snowflake_database.db_glacier_corp.fully_qualified_name
    object_type = "DATABASE"
  }
}

# Grant USAGE on snowhub_internal schema
resource "snowflake_grant_privileges_to_account_role" "role_iceberg_engineer-usage_schema_snowhub_internal" {
  account_role_name = snowflake_account_role.role_iceberg_engineer.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_snowhub_internal.fully_qualified_name
  }
}

# Grant USAGE on frostbyte_it schema
resource "snowflake_grant_privileges_to_account_role" "role_iceberg_engineer-usage_schema_frostbyte_it" {
  account_role_name = snowflake_account_role.role_iceberg_engineer.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_frostbyte_it.fully_qualified_name
  }
}

# Grant SELECT on BLIZZARD_SECURITY table
resource "snowflake_grant_privileges_to_account_role" "role_priv_iceberg_engineer-select_blizzard_security" {
  account_role_name = snowflake_account_role.role_iceberg_engineer.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_blizzard_security.fully_qualified_name
    object_type = "TABLE"
  }
}

# Grant SELECT on SNOW_API_TOKENS table
resource "snowflake_grant_privileges_to_account_role" "role_priv_iceberg_engineer-select_snow_api_tokens" {
  account_role_name = snowflake_account_role.role_iceberg_engineer.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_snow_api_tokens.fully_qualified_name
    object_type = "TABLE"
  }
}

# Grant SELECT on GLACIER_ROLE_ACCESS table
resource "snowflake_grant_privileges_to_account_role" "role_priv_iceberg_engineer-select_glacier_role_access" {
  account_role_name = snowflake_account_role.role_iceberg_engineer.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_glacier_role_access.fully_qualified_name
    object_type = "TABLE"
  }
}

resource "snowflake_grant_privileges_to_account_role" "role_permafrost_dev_usage_database" {
  account_role_name = snowflake_account_role.role_permafrost_dev.name
  privileges        = ["USAGE"]
  on_account_object {
    object_name = snowflake_database.db_glacier_corp.fully_qualified_name
    object_type = "DATABASE"
  }
}

# Grant USAGE on snowhub_internal schema
resource "snowflake_grant_privileges_to_account_role" "role_permafrost_dev_usage_schema_snowhub_internal" {
  account_role_name = snowflake_account_role.role_permafrost_dev.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_snowhub_internal.fully_qualified_name
  }
}

resource "snowflake_grant_privileges_to_account_role" "role_permafrost_dev_usage_schema_frostbyte_it" {
  account_role_name = snowflake_account_role.role_permafrost_dev.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_frostbyte_it.fully_qualified_name
  }
}

resource "snowflake_grant_privileges_to_account_role" "role_permafrost_dev_select_blizzard_security" {
  account_role_name = snowflake_account_role.role_permafrost_dev.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_blizzard_security.fully_qualified_name
    object_type = "TABLE"
  }
}

resource "snowflake_grant_privileges_to_account_role" "role_permafrost_dev_select_snow_api_tokens" {
  account_role_name = snowflake_account_role.role_permafrost_dev.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_snow_api_tokens.fully_qualified_name
    object_type = "TABLE"
  }
}

resource "snowflake_grant_privileges_to_account_role" "role_permafrost_dev_select_glacier_role_access" {
  account_role_name = snowflake_account_role.role_permafrost_dev.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_glacier_role_access.fully_qualified_name
    object_type = "TABLE"
  }
}


# Grant USAGE on GLACIER_CORP database
resource "snowflake_grant_privileges_to_account_role" "role_priv_arctic_analyst_usage_database" {
  account_role_name = snowflake_account_role.role_arctic_analyst.name
  privileges        = ["USAGE"]
  on_account_object {
    object_name = snowflake_database.db_glacier_corp.fully_qualified_name
    object_type = "DATABASE"
  }
}

# Grant USAGE on snowhub_internal schema
resource "snowflake_grant_privileges_to_account_role" "role_arctic_analyst_usage_schema_snowhub_internal" {
  account_role_name = snowflake_account_role.role_arctic_analyst.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_snowhub_internal.fully_qualified_name
  }
}

# Grant USAGE on frostbyte_it schema
resource "snowflake_grant_privileges_to_account_role" "role_arctic_analyst_usage_schema_frostbyte_it" {
  account_role_name = snowflake_account_role.role_arctic_analyst.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_frostbyte_it.fully_qualified_name
  }
}

# Grant SELECT on GLACIER_PAYMENTS table
resource "snowflake_grant_privileges_to_account_role" "role_priv_arctic_analyst_select_glacier_payments" {
  account_role_name = snowflake_account_role.role_arctic_analyst.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_glacier_payments.fully_qualified_name
    object_type = "TABLE"
  }
}

# Grant SELECT on VENDOR_ICEPORT table
resource "snowflake_grant_privileges_to_account_role" "role_priv_arctic_analyst_select_vendor_iceport" {
  account_role_name = snowflake_account_role.role_arctic_analyst.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_vendor_iceport.fully_qualified_name
    object_type = "TABLE"
  }
}

# Grant USAGE on GLACIER_CORP database
resource "snowflake_grant_privileges_to_account_role" "role_priv_arctic_analyst-usage_database" {
  account_role_name = snowflake_account_role.role_arctic_analyst.name
  privileges        = ["USAGE"]
  on_account_object {
    object_name = snowflake_database.db_glacier_corp.fully_qualified_name
    object_type = "DATABASE"
  }
}

# Grant USAGE on snowhub_internal schema
resource "snowflake_grant_privileges_to_account_role" "role_arctic_analyst-usage_schema_snowhub_internal" {
  account_role_name = snowflake_account_role.role_arctic_analyst.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_snowhub_internal.fully_qualified_name
  }
}

# Grant USAGE on frostbyte_it schema
resource "snowflake_grant_privileges_to_account_role" "role_arctic_analyst-usage_schema_frostbyte_it" {
  account_role_name = snowflake_account_role.role_arctic_analyst.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_frostbyte_it.fully_qualified_name
  }
}

# Grant SELECT on GLACIER_PAYMENTS table
resource "snowflake_grant_privileges_to_account_role" "role_priv_arctic_analyst-select_glacier_payments" {
  account_role_name = snowflake_account_role.role_arctic_analyst.name
  privileges        = ["SELECT", "INSERT"]
  on_schema_object {
    object_name = snowflake_table.table_glacier_payments.fully_qualified_name
    object_type = "TABLE"
  }
}

# Grant SELECT on VENDOR_ICEPORT table
resource "snowflake_grant_privileges_to_account_role" "role_priv_arctic_analyst-select_vendor_iceport" {
  account_role_name = snowflake_account_role.role_arctic_analyst.name
  privileges        = ["SELECT", "INSERT"]
  on_schema_object {
    object_name = snowflake_table.table_vendor_iceport.fully_qualified_name
    object_type = "TABLE"
  }
}


# Grant USAGE on GLACIER_CORP database
resource "snowflake_grant_privileges_to_account_role" "role_priv_glacier_reader-usage_database" {
  account_role_name = snowflake_account_role.role_glacier_reader.name
  privileges        = ["USAGE"]
  on_account_object {
    object_name = snowflake_database.db_glacier_corp.fully_qualified_name
    object_type = "DATABASE"
  }
}

# Grant USAGE on snowhub_internal schema
resource "snowflake_grant_privileges_to_account_role" "role_glacier_reader-usage_schema_snowhub_internal" {
  account_role_name = snowflake_account_role.role_glacier_reader.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_snowhub_internal.fully_qualified_name
  }
}

# Grant USAGE on frostbyte_it schema
resource "snowflake_grant_privileges_to_account_role" "role_glacier_reader-usage_schema_frostbyte_it" {
  account_role_name = snowflake_account_role.role_glacier_reader.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_snowhub_internal.fully_qualified_name
  }
}

# Grant SELECT on VENDOR_ICEPORT table
resource "snowflake_grant_privileges_to_account_role" "role_priv_glacier_reader-select_vendor_iceport" {
  account_role_name = snowflake_account_role.role_glacier_reader.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_vendor_iceport.fully_qualified_name
    object_type = "TABLE"
  }
}

# Grant SELECT on COLDSTREAM_USERS table
resource "snowflake_grant_privileges_to_account_role" "role_priv_glacier_reader-select_coldstream_users" {
  account_role_name = snowflake_account_role.role_glacier_reader.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_coldstream_users.fully_qualified_name
    object_type = "TABLE"
  }
}

# Grant SELECT on ICEBOUND_COMPLIANCE table
resource "snowflake_grant_privileges_to_account_role" "role_priv_glacier_reader-select_icebound_compliance" {
  account_role_name = snowflake_account_role.role_glacier_reader.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_icebound_compliance.fully_qualified_name
    object_type = "TABLE"
  }
}

# Grant USAGE on GLACIER_CORP database
resource "snowflake_grant_privileges_to_account_role" "role_priv_polar_guardian-usage_database" {
  account_role_name = snowflake_account_role.role_polar_guardian.name
  privileges        = ["USAGE"]
  on_account_object {
    object_name = snowflake_database.db_glacier_corp.fully_qualified_name
    object_type = "DATABASE"
  }
}

# Grant USAGE on snowhub_internal schema
resource "snowflake_grant_privileges_to_account_role" "role_polar_guardian-usage_schema_snowhub_internal" {
  account_role_name = snowflake_account_role.role_polar_guardian.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_snowhub_internal.fully_qualified_name
  }
}

# Grant USAGE on frostbyte_it schema
resource "snowflake_grant_privileges_to_account_role" "role_polar_guardian-usage_schema_frostbyte_it" {
  account_role_name = snowflake_account_role.role_polar_guardian.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_frostbyte_it.fully_qualified_name
  }
}

# Table grants — SELECT + INSERT
resource "snowflake_grant_privileges_to_account_role" "role_priv_polar_guardian-access_vendor_iceport" {
  account_role_name = snowflake_account_role.role_polar_guardian.name
  privileges        = ["SELECT", "INSERT"]
  on_schema_object {
    object_name = snowflake_table.table_vendor_iceport.fully_qualified_name
    object_type = "TABLE"
  }
}

resource "snowflake_grant_privileges_to_account_role" "role_priv_polar_guardian-access_coldstream_users" {
  account_role_name = snowflake_account_role.role_polar_guardian.name
  privileges        = ["SELECT", "INSERT"]
  on_schema_object {
    object_name = snowflake_table.table_coldstream_users.fully_qualified_name
    object_type = "TABLE"
  }
}

resource "snowflake_grant_privileges_to_account_role" "role_priv_polar_guardian-access_snow_api_tokens" {
  account_role_name = snowflake_account_role.role_polar_guardian.name
  privileges        = ["SELECT", "INSERT"]
  on_schema_object {
    object_name = snowflake_table.table_snow_api_tokens.fully_qualified_name
    object_type = "TABLE"
  }
}

resource "snowflake_grant_privileges_to_account_role" "role_priv_polar_guardian-access_icebound_compliance" {
  account_role_name = snowflake_account_role.role_polar_guardian.name
  privileges        = ["SELECT", "INSERT"]
  on_schema_object {
    object_name = snowflake_table.table_icebound_compliance.fully_qualified_name
    object_type = "TABLE"
  }
}

resource "snowflake_grant_privileges_to_account_role" "role_priv_polar_guardian-access_glacier_role_access" {
  account_role_name = snowflake_account_role.role_polar_guardian.name
  privileges        = ["SELECT", "INSERT"]
  on_schema_object {
    object_name = snowflake_table.table_glacier_role_access.fully_qualified_name
    object_type = "TABLE"
  }
}

resource "snowflake_grant_privileges_to_account_role" "role_priv_polar_guardian-access_polar_crypt_vault" {
  account_role_name = snowflake_account_role.role_polar_guardian.name
  privileges        = ["SELECT", "INSERT"]
  on_schema_object {
    object_name = snowflake_table.table_polar_crypt_vault.fully_qualified_name
    object_type = "TABLE"
  }
}

# Grant USAGE on GLACIER_CORP database
resource "snowflake_grant_privileges_to_account_role" "role_priv_frozen_auditor-usage_database" {
  account_role_name = snowflake_account_role.role_frozen_auditor.name
  privileges        = ["USAGE"]
  on_account_object {
    object_name = snowflake_database.db_glacier_corp.fully_qualified_name
    object_type = "DATABASE"
  }
}

# Grant USAGE on snowhub_internal schema
resource "snowflake_grant_privileges_to_account_role" "role_frozen_auditor-usage_schema_snowhub_internal" {
  account_role_name = snowflake_account_role.role_frozen_auditor.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_snowhub_internal.fully_qualified_name
  }
}

# Grant USAGE on frostbyte_it schema
resource "snowflake_grant_privileges_to_account_role" "role_frozen_auditor-usage_schema_frostbyte_it" {
  account_role_name = snowflake_account_role.role_frozen_auditor.name
  privileges        = ["USAGE"]
  on_schema {
    schema_name = snowflake_schema.schema_frostbyte_it.fully_qualified_name
  }
}

# Grant SELECT and INSERT on VENDOR_ICEPORT
resource "snowflake_grant_privileges_to_account_role" "role_priv_frozen_auditor-access_vendor_iceport" {
  account_role_name = snowflake_account_role.role_frozen_auditor.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_vendor_iceport.fully_qualified_name
    object_type = "TABLE"
  }
}

# Grant SELECT and INSERT on COLDSTREAM_USERS
resource "snowflake_grant_privileges_to_account_role" "role_priv_frozen_auditor-access_coldstream_users" {
  account_role_name = snowflake_account_role.role_frozen_auditor.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_coldstream_users.fully_qualified_name
    object_type = "TABLE"
  }
}

# Grant SELECT and INSERT on SNOW_API_TOKENS
resource "snowflake_grant_privileges_to_account_role" "role_priv_frozen_auditor-access_snow_api_tokens" {
  account_role_name = snowflake_account_role.role_frozen_auditor.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_snow_api_tokens.fully_qualified_name
    object_type = "TABLE"
  }
}

# Grant SELECT and INSERT on ICEBOUND_COMPLIANCE
resource "snowflake_grant_privileges_to_account_role" "role_priv_frozen_auditor-access_icebound_compliance" {
  account_role_name = snowflake_account_role.role_frozen_auditor.name
  privileges        = ["SELECT"]
  on_schema_object {
    object_name = snowflake_table.table_icebound_compliance.fully_qualified_name
    object_type = "TABLE"
  }
}
