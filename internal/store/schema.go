package store

const schemaVersion = 4

const schema = `
CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS access_tokens (
  token_hash TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  expires_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'Enabled',
  tenant_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resource_groups (
  subscription_id TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL,
  tags_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (subscription_id, name)
);

CREATE TABLE IF NOT EXISTS role_assignments (
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  role_definition_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  principal_type TEXT NOT NULL DEFAULT 'ServicePrincipal'
);

CREATE TABLE IF NOT EXISTS storage_accounts (
  subscription_id TEXT NOT NULL,
  resource_group TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT 'eastus',
  account_key_sealed BLOB NOT NULL,
  PRIMARY KEY (subscription_id, resource_group, name)
);

CREATE TABLE IF NOT EXISTS blob_containers (
  account TEXT NOT NULL,
  name TEXT NOT NULL,
  PRIMARY KEY (account, name)
);

CREATE TABLE IF NOT EXISTS blobs (
  account TEXT NOT NULL,
  container TEXT NOT NULL,
  name TEXT NOT NULL,
  content BLOB NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  PRIMARY KEY (account, container, name)
);

CREATE TABLE IF NOT EXISTS storage_queues (
  account TEXT NOT NULL,
  name TEXT NOT NULL,
  PRIMARY KEY (account, name)
);

CREATE TABLE IF NOT EXISTS storage_queue_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account TEXT NOT NULL,
  queue TEXT NOT NULL,
  body TEXT NOT NULL,
  inserted_at TEXT NOT NULL,
  visible_after TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS tables (
  account TEXT NOT NULL,
  table_name TEXT NOT NULL,
  PRIMARY KEY (account, table_name)
);

CREATE TABLE IF NOT EXISTS table_entities (
  account TEXT NOT NULL,
  table_name TEXT NOT NULL,
  partition_key TEXT NOT NULL,
  row_key TEXT NOT NULL,
  etag TEXT NOT NULL,
  properties_json TEXT NOT NULL,
  PRIMARY KEY (account, table_name, partition_key, row_key)
);

CREATE TABLE IF NOT EXISTS keyvaults (
  subscription_id TEXT NOT NULL,
  resource_group TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT 'eastus',
  PRIMARY KEY (subscription_id, resource_group, name)
);

CREATE TABLE IF NOT EXISTS keyvault_secrets (
  vault TEXT NOT NULL,
  name TEXT NOT NULL,
  value_sealed BLOB NOT NULL,
  version TEXT NOT NULL,
  PRIMARY KEY (vault, name, version)
);

CREATE TABLE IF NOT EXISTS keyvault_keys (
  vault TEXT NOT NULL,
  name TEXT NOT NULL,
  key_sealed BLOB NOT NULL,
  version TEXT NOT NULL,
  PRIMARY KEY (vault, name, version)
);

CREATE TABLE IF NOT EXISTS servicebus_namespaces (
  subscription_id TEXT NOT NULL,
  resource_group TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT 'eastus',
  sas_key_sealed BLOB NOT NULL,
  PRIMARY KEY (subscription_id, resource_group, name)
);

CREATE TABLE IF NOT EXISTS servicebus_queues (
  namespace TEXT NOT NULL,
  name TEXT NOT NULL,
  PRIMARY KEY (namespace, name)
);

CREATE TABLE IF NOT EXISTS servicebus_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  namespace TEXT NOT NULL,
  queue TEXT NOT NULL,
  body BLOB NOT NULL,
  locked_until TEXT NOT NULL DEFAULT '',
  inserted_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS appconfig_stores (
  subscription_id TEXT NOT NULL,
  resource_group TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT 'eastus',
  PRIMARY KEY (subscription_id, resource_group, name)
);

CREATE TABLE IF NOT EXISTS appconfig_kvs (
  store TEXT NOT NULL,
  key TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  value TEXT NOT NULL,
  PRIMARY KEY (store, key, label)
);

CREATE TABLE IF NOT EXISTS function_apps (
  subscription_id TEXT NOT NULL,
  resource_group TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT 'eastus',
  mock_response TEXT NOT NULL DEFAULT 'ok',
  PRIMARY KEY (subscription_id, resource_group, name)
);

CREATE TABLE IF NOT EXISTS activity_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  caller TEXT NOT NULL,
  operation TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  status TEXT NOT NULL,
  message TEXT NOT NULL DEFAULT '',
  client_ip TEXT NOT NULL DEFAULT '',
  identity_json TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  value REAL NOT NULL,
  timestamp TEXT NOT NULL,
  resource_id TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS entra_signing_keys (
  kid TEXT PRIMARY KEY,
  private_key_sealed BLOB NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS managed_identities (
  subscription_id TEXT NOT NULL,
  resource_group TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT 'eastus',
  principal_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  PRIMARY KEY (subscription_id, resource_group, name)
);

CREATE TABLE IF NOT EXISTS keyvault_deleted_secrets (
  vault TEXT NOT NULL,
  name TEXT NOT NULL,
  value_sealed BLOB NOT NULL,
  version TEXT NOT NULL,
  deleted_at TEXT NOT NULL,
  PRIMARY KEY (vault, name, version)
);

CREATE TABLE IF NOT EXISTS entra_apps (
  tenant_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, app_id)
);

CREATE TABLE IF NOT EXISTS system_assigned_identities (
  subscription_id TEXT NOT NULL,
  resource_group TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT 'eastus',
  principal_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  PRIMARY KEY (subscription_id, resource_group, name)
);

CREATE TABLE IF NOT EXISTS keyvault_certificates (
  vault TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  cert_pem_sealed BLOB NOT NULL,
  policy_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (vault, name, version)
);

CREATE TABLE IF NOT EXISTS appconfig_feature_flags (
  store TEXT NOT NULL,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  conditions_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (store, name)
);

CREATE TABLE IF NOT EXISTS appconfig_snapshots (
  store TEXT NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ready',
  created_at TEXT NOT NULL,
  PRIMARY KEY (store, name)
);

CREATE TABLE IF NOT EXISTS servicebus_topics (
  namespace TEXT NOT NULL,
  name TEXT NOT NULL,
  PRIMARY KEY (namespace, name)
);

CREATE TABLE IF NOT EXISTS servicebus_subscriptions (
  namespace TEXT NOT NULL,
  topic TEXT NOT NULL,
  name TEXT NOT NULL,
  filter_sql TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (namespace, topic, name)
);

CREATE TABLE IF NOT EXISTS servicebus_topic_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  namespace TEXT NOT NULL,
  topic TEXT NOT NULL,
  subscription TEXT NOT NULL,
  body BLOB NOT NULL,
  inserted_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS eventhubs_namespaces (
  subscription_id TEXT NOT NULL,
  resource_group TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT 'eastus',
  PRIMARY KEY (subscription_id, resource_group, name)
);

CREATE TABLE IF NOT EXISTS eventhubs_hubs (
  namespace TEXT NOT NULL,
  name TEXT NOT NULL,
  partition_count INTEGER NOT NULL DEFAULT 2,
  PRIMARY KEY (namespace, name)
);

CREATE TABLE IF NOT EXISTS eventhubs_consumer_groups (
  namespace TEXT NOT NULL,
  hub TEXT NOT NULL,
  name TEXT NOT NULL,
  PRIMARY KEY (namespace, hub, name)
);

CREATE TABLE IF NOT EXISTS eventhubs_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  namespace TEXT NOT NULL,
  hub TEXT NOT NULL,
  partition_id TEXT NOT NULL,
  body BLOB NOT NULL,
  inserted_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS eventgrid_topics (
  subscription_id TEXT NOT NULL,
  resource_group TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT 'eastus',
  PRIMARY KEY (subscription_id, resource_group, name)
);

CREATE TABLE IF NOT EXISTS eventgrid_subscriptions (
  topic TEXT NOT NULL,
  name TEXT NOT NULL,
  destination_url TEXT NOT NULL DEFAULT '',
  filter_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (topic, name)
);

CREATE TABLE IF NOT EXISTS eventgrid_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  topic TEXT NOT NULL,
  body_json TEXT NOT NULL,
  delivered INTEGER NOT NULL DEFAULT 0,
  inserted_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cosmos_accounts (
  subscription_id TEXT NOT NULL,
  resource_group TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT 'eastus',
  key_sealed BLOB NOT NULL,
  PRIMARY KEY (subscription_id, resource_group, name)
);

CREATE TABLE IF NOT EXISTS cosmos_databases (
  account TEXT NOT NULL,
  name TEXT NOT NULL,
  PRIMARY KEY (account, name)
);

CREATE TABLE IF NOT EXISTS cosmos_containers (
  account TEXT NOT NULL,
  database_name TEXT NOT NULL,
  name TEXT NOT NULL,
  partition_key TEXT NOT NULL DEFAULT '/id',
  PRIMARY KEY (account, database_name, name)
);

CREATE TABLE IF NOT EXISTS cosmos_items (
  account TEXT NOT NULL,
  database_name TEXT NOT NULL,
  container TEXT NOT NULL,
  id TEXT NOT NULL,
  partition_key_value TEXT NOT NULL,
  body_json TEXT NOT NULL,
  PRIMARY KEY (account, database_name, container, id, partition_key_value)
);

CREATE TABLE IF NOT EXISTS arm_lab_resources (
  provider TEXT NOT NULL,
  subscription_id TEXT NOT NULL,
  resource_group TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL DEFAULT 'eastus',
  properties_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (provider, subscription_id, resource_group, name)
);

CREATE TABLE IF NOT EXISTS log_analytics_rows (
  workspace TEXT NOT NULL,
  table_name TEXT NOT NULL,
  row_json TEXT NOT NULL,
  id INTEGER PRIMARY KEY AUTOINCREMENT
);

CREATE TABLE IF NOT EXISTS email_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  service_name TEXT NOT NULL,
  to_addr TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  inserted_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entra_users (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  user_principal_name TEXT NOT NULL,
  display_name TEXT NOT NULL,
  mail TEXT NOT NULL DEFAULT '',
  department TEXT NOT NULL DEFAULT '',
  job_title TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entra_groups (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  mail TEXT NOT NULL DEFAULT '',
  security_enabled INTEGER NOT NULL DEFAULT 1,
  membership_rule TEXT NOT NULL DEFAULT '',
  membership_rule_processing_state TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entra_group_members (
  group_id TEXT NOT NULL,
  member_id TEXT NOT NULL,
  member_type TEXT NOT NULL,
  PRIMARY KEY (group_id, member_id)
);

CREATE TABLE IF NOT EXISTS entra_service_principals (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entra_devices (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  device_id TEXT NOT NULL,
  operating_system TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entra_directory_roles (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  template_id TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entra_directory_role_members (
  role_id TEXT NOT NULL,
  member_id TEXT NOT NULL,
  PRIMARY KEY (role_id, member_id)
);

CREATE TABLE IF NOT EXISTS entra_owners (
  resource_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  owner_type TEXT NOT NULL DEFAULT 'user',
  PRIMARY KEY (resource_id, owner_id)
);

CREATE TABLE IF NOT EXISTS entra_fics (
  id TEXT PRIMARY KEY,
  app_object_id TEXT NOT NULL,
  name TEXT NOT NULL,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  audiences_json TEXT NOT NULL,
  claims_matching_expression TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS entra_passwords (
  id TEXT PRIMARY KEY,
  resource_id TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  secret_hash TEXT NOT NULL,
  hint TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entra_key_credentials (
  id TEXT PRIMARY KEY,
  resource_id TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  key_pem TEXT NOT NULL,
  usage TEXT NOT NULL DEFAULT 'Verify',
  key_type TEXT NOT NULL DEFAULT 'AsymmetricX509Cert'
);

CREATE TABLE IF NOT EXISTS entra_app_role_assignments (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  app_role_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'
);

CREATE TABLE IF NOT EXISTS entra_unified_role_assignments (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  role_definition_id TEXT NOT NULL,
  directory_scope_id TEXT NOT NULL DEFAULT '/'
);

CREATE TABLE IF NOT EXISTS entra_ca_policies (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  body_json TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_codes (
  device_code TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS management_groups (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  parent_id TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS arg_resources (
  id TEXT PRIMARY KEY,
  table_name TEXT NOT NULL,
  type TEXT NOT NULL,
  name TEXT NOT NULL,
  subscription_id TEXT NOT NULL DEFAULT '',
  resource_group TEXT NOT NULL DEFAULT '',
  tenant_id TEXT NOT NULL DEFAULT '',
  properties_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS diagnostic_settings (
  id TEXT PRIMARY KEY,
  resource_id TEXT NOT NULL,
  name TEXT NOT NULL,
  workspace_id TEXT NOT NULL DEFAULT '',
  properties_json TEXT NOT NULL DEFAULT '{}'
);
`
