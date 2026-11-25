-- Removes the organization feature from installs that had it. Fresh installs (schema from
-- 0001_init.sql after this change) already lack these objects and must not run this file.
-- Take a D1 backup first: the drops are irreversible.
--
-- Apply once, before or after deploying a build that no longer serves organizations:
--   wrangler d1 execute nodewarden --remote --file migrations/0002_drop_organizations.sql

DROP INDEX IF EXISTS idx_events_organization_date;
DROP INDEX IF EXISTS idx_events_cipher_date;
DROP INDEX IF EXISTS idx_events_date;
DROP TABLE IF EXISTS events;

DROP INDEX IF EXISTS idx_collection_ciphers_cipher;
DROP TABLE IF EXISTS collection_ciphers;

DROP INDEX IF EXISTS idx_collection_groups_group;
DROP TABLE IF EXISTS collection_groups;

DROP INDEX IF EXISTS idx_group_members_member;
DROP TABLE IF EXISTS group_members;

DROP INDEX IF EXISTS idx_organization_groups_organization;
DROP TABLE IF EXISTS organization_groups;

DROP INDEX IF EXISTS idx_collection_members_member;
DROP TABLE IF EXISTS collection_members;

DROP INDEX IF EXISTS idx_collections_organization;
DROP TABLE IF EXISTS collections;

DROP TABLE IF EXISTS organization_policies;

DROP INDEX IF EXISTS idx_organization_members_user;
DROP TABLE IF EXISTS organization_members;

-- The cipher column references organizations, so it goes before the parent table.
DROP INDEX IF EXISTS idx_ciphers_organization;
ALTER TABLE ciphers DROP COLUMN organization_id;

DROP TABLE IF EXISTS organizations;
