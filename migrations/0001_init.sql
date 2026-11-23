PRAGMA foreign_keys = ON;

-- IMPORTANT:
-- This is the initial D1 schema. Keep it in sync with
-- src/services/storage-schema.ts (SCHEMA_STATEMENTS).
-- Any new table/column/index must be added to both places together.
--
-- WHEN CHANGING THIS:
-- - Also bump STORAGE_SCHEMA_VERSION in src/services/storage.ts.
-- - If the new table stores persistent data, update backup export/import.
-- - Keep src/services/storage-schema.ts idempotent for existing installs.

CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT,
  master_password_hint TEXT,
  master_password_hash TEXT NOT NULL,
  key TEXT NOT NULL,
  private_key TEXT,
  public_key TEXT,
  kdf_type INTEGER NOT NULL,
  kdf_iterations INTEGER NOT NULL,
  kdf_memory INTEGER,
  kdf_parallelism INTEGER,
  security_stamp TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  status TEXT NOT NULL DEFAULT 'active',
  verify_devices INTEGER NOT NULL DEFAULT 0,
  totp_secret TEXT,
  totp_recovery_code TEXT,
  api_key TEXT,
  user_key_id TEXT,
  avatar_color TEXT,
  email_2fa TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domain_settings (
  user_id TEXT PRIMARY KEY,
  equivalent_domains TEXT NOT NULL DEFAULT '[]',
  custom_equivalent_domains TEXT NOT NULL DEFAULT '[]',
  excluded_global_equivalent_domains TEXT NOT NULL DEFAULT '[]',
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Per-user sync revision date
CREATE TABLE IF NOT EXISTS user_revisions (
  user_id TEXT PRIMARY KEY,
  revision_date TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ciphers (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  type INTEGER NOT NULL,
  folder_id TEXT,
  name TEXT,
  notes TEXT,
  favorite INTEGER NOT NULL DEFAULT 0,
  data TEXT NOT NULL,
  reprompt INTEGER,
  key TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  archived_at TEXT,
  deleted_at TEXT,
  -- Set for an organization cipher; user_id then records who created it.
  organization_id TEXT REFERENCES organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ciphers_user_updated ON ciphers(user_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_ciphers_user_archived ON ciphers(user_id, archived_at);
CREATE INDEX IF NOT EXISTS idx_ciphers_user_deleted ON ciphers(user_id, deleted_at);
CREATE INDEX IF NOT EXISTS idx_ciphers_user_deleted_updated ON ciphers(user_id, deleted_at, updated_at);
CREATE INDEX IF NOT EXISTS idx_ciphers_user_folder ON ciphers(user_id, folder_id);

CREATE TABLE IF NOT EXISTS folders (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_folders_user_updated ON folders(user_id, updated_at);

CREATE TABLE IF NOT EXISTS attachments (
  id TEXT PRIMARY KEY,
  cipher_id TEXT NOT NULL,
  file_name TEXT NOT NULL,
  size INTEGER NOT NULL,
  size_name TEXT NOT NULL,
  key TEXT,
  FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_attachments_cipher ON attachments(cipher_id);

CREATE TABLE IF NOT EXISTS sends (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  type INTEGER NOT NULL,
  name TEXT NOT NULL,
  notes TEXT,
  data TEXT NOT NULL,
  key TEXT NOT NULL,
  password_hash TEXT,
  password_salt TEXT,
  password_iterations INTEGER,
  auth_type INTEGER NOT NULL DEFAULT 2,
  emails TEXT,
  max_access_count INTEGER,
  access_count INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  hide_email INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expiration_date TEXT,
  deletion_date TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sends_user_updated ON sends(user_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_sends_user_deletion ON sends(user_id, deletion_date);
CREATE INDEX IF NOT EXISTS idx_sends_user_updated_id ON sends(user_id, updated_at, id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  device_identifier TEXT,
  device_session_stamp TEXT,
  security_stamp TEXT,
  created_at INTEGER,
  last_used_at INTEGER,
  absolute_expires_at INTEGER,
  client_type TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);

CREATE TABLE IF NOT EXISTS invites (
  code TEXT PRIMARY KEY,
  created_by TEXT NOT NULL,
  used_by TEXT,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (used_by) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_invites_status_expires ON invites(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_invites_created_by ON invites(created_by, created_at);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT,
  action TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'system',
  level TEXT NOT NULL DEFAULT 'info',
  target_type TEXT,
  target_id TEXT,
  metadata TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_created ON audit_logs(actor_user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_category_created ON audit_logs(category, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_level_created ON audit_logs(level, created_at);

CREATE TABLE IF NOT EXISTS devices (
  user_id TEXT NOT NULL,
  device_identifier TEXT NOT NULL,
  name TEXT NOT NULL,
  type INTEGER NOT NULL,
  session_stamp TEXT,
  encrypted_user_key TEXT,
  encrypted_public_key TEXT,
  encrypted_private_key TEXT,
  push_uuid TEXT,
  push_token TEXT,
  banned INTEGER NOT NULL DEFAULT 0,
  banned_at TEXT,
  device_note TEXT,
  last_seen_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, device_identifier),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_devices_user_updated ON devices(user_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_devices_user_last_seen ON devices(user_id, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_devices_user_push ON devices(user_id, push_token);

CREATE TABLE IF NOT EXISTS auth_requests (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  organization_id TEXT,
  type INTEGER NOT NULL,
  request_device_identifier TEXT NOT NULL,
  request_device_type INTEGER NOT NULL,
  request_ip_address TEXT,
  request_country_name TEXT,
  response_device_identifier TEXT,
  access_code TEXT NOT NULL,
  public_key TEXT NOT NULL,
  key TEXT,
  master_password_hash TEXT,
  approved INTEGER,
  creation_date TEXT NOT NULL,
  response_date TEXT,
  authentication_date TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_auth_requests_user_created
  ON auth_requests(user_id, creation_date);
CREATE INDEX IF NOT EXISTS idx_auth_requests_user_pending
  ON auth_requests(user_id, approved, response_date, authentication_date, creation_date);
CREATE INDEX IF NOT EXISTS idx_auth_requests_device_pending
  ON auth_requests(user_id, request_device_identifier, creation_date);

CREATE TABLE IF NOT EXISTS trusted_two_factor_device_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  device_identifier TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_trusted_two_factor_device_tokens_user_device
  ON trusted_two_factor_device_tokens(user_id, device_identifier);

CREATE TABLE IF NOT EXISTS totp_login_replays (
  user_id TEXT NOT NULL,
  time_counter INTEGER NOT NULL,
  consumed_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, time_counter),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_totp_login_replays_consumed_at
  ON totp_login_replays(consumed_at);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  purpose TEXT NOT NULL DEFAULT 'login',
  name TEXT NOT NULL,
  public_key TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  type TEXT,
  aa_guid TEXT,
  transports TEXT,
  encrypted_user_key TEXT,
  encrypted_public_key TEXT,
  encrypted_private_key TEXT,
  supports_prf INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id
  ON webauthn_credentials(credential_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user
  ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_updated
  ON webauthn_credentials(user_id, updated_at);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
  challenge_hash TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  user_id TEXT,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires
  ON webauthn_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user_scope
  ON webauthn_challenges(user_id, scope);

-- Organizations
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  billing_email TEXT NOT NULL,
  private_key TEXT,
  public_key TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  api_key TEXT,
  api_key_revision_date TEXT
);

-- status: 0 invited, 1 accepted, 2 confirmed; a revoked member keeps its status minus 128 (clients see -1). type: 0 owner, 1 admin, 2 user, 4 custom.
CREATE TABLE IF NOT EXISTS organization_members (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  akey TEXT NOT NULL DEFAULT '',
  status INTEGER NOT NULL,
  type INTEGER NOT NULL,
  access_all INTEGER NOT NULL DEFAULT 0,
  reset_password_key TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (organization_id, user_id),
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_organization_members_user
  ON organization_members(user_id);

CREATE TABLE IF NOT EXISTS collections (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  name TEXT NOT NULL,
  external_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_collections_organization
  ON collections(organization_id);

CREATE TABLE IF NOT EXISTS collection_members (
  collection_id TEXT NOT NULL,
  member_id TEXT NOT NULL,
  read_only INTEGER NOT NULL DEFAULT 0,
  hide_passwords INTEGER NOT NULL DEFAULT 0,
  manage INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (collection_id, member_id),
  FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE,
  FOREIGN KEY (member_id) REFERENCES organization_members(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_collection_members_member
  ON collection_members(member_id);
CREATE INDEX IF NOT EXISTS idx_ciphers_organization
  ON ciphers(organization_id);

CREATE TABLE IF NOT EXISTS collection_ciphers (
  collection_id TEXT NOT NULL,
  cipher_id TEXT NOT NULL,
  PRIMARY KEY (collection_id, cipher_id),
  FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE,
  FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_collection_ciphers_cipher
  ON collection_ciphers(cipher_id);

CREATE TABLE IF NOT EXISTS organization_groups (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  name TEXT NOT NULL,
  external_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_organization_groups_organization
  ON organization_groups(organization_id);

CREATE TABLE IF NOT EXISTS group_members (
  group_id TEXT NOT NULL,
  member_id TEXT NOT NULL,
  PRIMARY KEY (group_id, member_id),
  FOREIGN KEY (group_id) REFERENCES organization_groups(id) ON DELETE CASCADE,
  FOREIGN KEY (member_id) REFERENCES organization_members(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_group_members_member
  ON group_members(member_id);

CREATE TABLE IF NOT EXISTS collection_groups (
  collection_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  read_only INTEGER NOT NULL DEFAULT 0,
  hide_passwords INTEGER NOT NULL DEFAULT 0,
  manage INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (collection_id, group_id),
  FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE,
  FOREIGN KEY (group_id) REFERENCES organization_groups(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_collection_groups_group
  ON collection_groups(group_id);

-- type: Bitwarden's PolicyType. data: the policy's JSON, stored as the client sent it.
CREATE TABLE IF NOT EXISTS organization_policies (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  type INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  data TEXT NOT NULL DEFAULT 'null',
  updated_at TEXT NOT NULL,
  UNIQUE (organization_id, type),
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- Rate limiting
CREATE TABLE IF NOT EXISTS login_attempts_ip (
  ip TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL,
  locked_until INTEGER,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS used_attachment_download_tokens (
  jti TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);

-- Emergency access: type 0 view, 1 takeover; status 0 invited, 1 accepted, 2 confirmed,
-- 3 recovery initiated, 4 recovery approved.
CREATE TABLE IF NOT EXISTS emergency_access (
  id TEXT PRIMARY KEY,
  grantor_id TEXT NOT NULL,
  grantee_id TEXT,
  email TEXT,
  key_encrypted TEXT,
  type INTEGER NOT NULL,
  status INTEGER NOT NULL,
  wait_time_days INTEGER NOT NULL,
  recovery_initiated_at TEXT,
  last_notification_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (grantor_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (grantee_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_emergency_access_pair
  ON emergency_access(grantor_id, grantee_id);
CREATE INDEX IF NOT EXISTS idx_emergency_access_grantee
  ON emergency_access(grantee_id);

-- Organization event log. Only organization_id is a foreign key: an event outlives the cipher,
-- member or user it names, and goes with its organization.
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  type INTEGER NOT NULL,
  organization_id TEXT NOT NULL,
  user_id TEXT,
  cipher_id TEXT,
  collection_id TEXT,
  group_id TEXT,
  member_id TEXT,
  policy_id TEXT,
  acting_user_id TEXT,
  device_type INTEGER,
  ip_address TEXT,
  event_date TEXT NOT NULL,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_events_organization_date
  ON events(organization_id, event_date);
CREATE INDEX IF NOT EXISTS idx_events_cipher_date
  ON events(cipher_id, event_date);
CREATE INDEX IF NOT EXISTS idx_events_date
  ON events(event_date);

-- Short-lived codes and link tokens sent by email. Runtime state: not exported in backups.
CREATE TABLE IF NOT EXISTS email_codes (
  user_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, purpose),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
