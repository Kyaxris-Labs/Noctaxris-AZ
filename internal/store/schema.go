package store

const schemaVersion = 1

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
  inserted_at TEXT NOT NULL
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
  message TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  value REAL NOT NULL,
  timestamp TEXT NOT NULL,
  resource_id TEXT NOT NULL DEFAULT ''
);
`
