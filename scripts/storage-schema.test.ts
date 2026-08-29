import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { SCHEMA_STATEMENTS } from '../src/services/storage-schema';
import { PERSONAL_CIPHER_ONLY } from '../src/services/storage-cipher-repo';

// Mirrors executeSchemaStatement: re-running the bootstrap must be a no-op, and
// ALTER TABLE ADD COLUMN always fails once the column exists.
function applySchema(db: DatabaseSync): void {
  for (const statement of SCHEMA_STATEMENTS) {
    try {
      db.exec(statement);
    } catch (error) {
      const message = String(error instanceof Error ? error.message : error).toLowerCase();
      if (message.includes('already exists') || message.includes('duplicate column name')) continue;
      throw new Error(`schema statement failed: ${statement}\n${message}`);
    }
  }
}

function freshDb(): DatabaseSync {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  applySchema(db);
  return db;
}

test('the runtime schema bootstrap executes against sqlite and is idempotent', () => {
  const db = freshDb();
  // Second pass proves every statement is safe to replay, which D1 does.
  applySchema(db);

  const tables = new Set(
    db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((row: any) => String(row.name))
  );
  for (const expected of [
    'users', 'ciphers', 'folders', 'organizations', 'organization_members', 'collections',
    'collection_items', 'organization_invitations', 'policies', 'sso_configs', 'sso_states',
    'sso_codes', 'scim_configs', 'scim_users',
  ]) {
    assert.equal(tables.has(expected), true, `missing table ${expected}`);
  }
  db.close();
});

test('sso_states carries the nonce column used for id token replay protection', () => {
  const db = freshDb();
  const columns = db.prepare('PRAGMA table_info(sso_states)').all().map((row: any) => String(row.name));
  assert.equal(columns.includes('nonce'), true);

  db.exec("INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES('u1', 'a@b.c', 'h', 'k', 0, 600000, 's', 'now', 'now')");
  db.exec("INSERT INTO organizations(id, name, owner_id, created_at, updated_at) VALUES('org-1', 'Acme', 'u1', 'now', 'now')");
  db.exec("INSERT INTO sso_states(state, organization_id, redirect_uri, code_challenge, nonce, expires_at, created_at) VALUES('st', 'org-1', 'https://x/', 'cc', 'nonce-1', 1, 1)");
  const row: any = db.prepare("SELECT nonce FROM sso_states WHERE state = 'st'").get();
  assert.equal(row.nonce, 'nonce-1');
  db.close();
});

test('the bootstrap repairs organization ciphers that carry personal state', () => {
  const db = freshDb();
  db.exec("INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES('u1', 'a@b.c', 'h', 'k', 0, 600000, 's', 'now', 'now')");
  db.exec("INSERT INTO folders(id, user_id, name, created_at, updated_at) VALUES('f1', 'u1', 'enc', 'now', 'now')");
  db.exec("INSERT INTO organizations(id, name, owner_id, created_at, updated_at) VALUES('org-1', 'Acme', 'u1', 'now', 'now')");
  db.exec("INSERT INTO collections(id, organization_id, name, created_at, updated_at) VALUES('col-1', 'org-1', 'enc', 'now', 'now')");

  // Contaminated org cipher: organizationId AND a stale folderId in the data
  // blob (parseCipherRow falls back to the JSON when the column is NULL).
  db.exec("INSERT INTO ciphers(id, user_id, type, folder_id, favorite, archived_at, data, created_at, updated_at) VALUES('c1', 'u1', 1, 'f1', 1, 'now', '{\"organizationId\":\"org-1\",\"folderId\":\"f1\"}', 'now', 'now')");
  // Contaminated org cipher: reachable only through a collection.
  db.exec("INSERT INTO ciphers(id, user_id, type, folder_id, favorite, data, created_at, updated_at) VALUES('c2', 'u1', 1, 'f1', 1, '{}', 'now', 'now')");
  db.exec("INSERT INTO collection_items(collection_id, cipher_id) VALUES('col-1', 'c2')");
  // A personal cipher must keep its folder and favorite.
  db.exec("INSERT INTO ciphers(id, user_id, type, folder_id, favorite, data, created_at, updated_at) VALUES('c3', 'u1', 1, 'f1', 1, '{}', 'now', 'now')");
  // Malformed data must not break the json_extract guard.
  db.exec("INSERT INTO ciphers(id, user_id, type, folder_id, favorite, data, created_at, updated_at) VALUES('c4', 'u1', 1, 'f1', 1, 'not json', 'now', 'now')");

  applySchema(db);

  const rows = new Map(
    db.prepare('SELECT id, folder_id, favorite, archived_at FROM ciphers').all().map((row: any) => [String(row.id), row])
  );
  for (const id of ['c1', 'c2']) {
    assert.equal(rows.get(id)!.folder_id, null, `${id} kept a folder`);
    assert.equal(rows.get(id)!.favorite, 0, `${id} kept a favorite`);
  }
  // The repair must also clear archive state and the JSON copy of folderId,
  // which reads fall back to when the column is NULL.
  assert.equal((db.prepare("SELECT archived_at FROM ciphers WHERE id = 'c1'").get() as any).archived_at, null);
  const repairedData = JSON.parse(String((db.prepare("SELECT data FROM ciphers WHERE id = 'c1'").get() as any).data));
  assert.equal(repairedData.folderId, null);
  assert.equal(rows.get('c3')!.folder_id, 'f1');
  assert.equal(rows.get('c3')!.favorite, 1);
  assert.equal(rows.get('c4')!.folder_id, 'f1');
  db.close();
});

test('deleting an organization does not cascade into its members ciphers', () => {
  const db = freshDb();
  db.exec("INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES('u1', 'a@b.c', 'h', 'k', 0, 600000, 's', 'now', 'now')");
  db.exec("INSERT INTO organizations(id, name, owner_id, created_at, updated_at) VALUES('org-1', 'Acme', 'u1', 'now', 'now')");
  db.exec("INSERT INTO collections(id, organization_id, name, created_at, updated_at) VALUES('col-1', 'org-1', 'enc', 'now', 'now')");
  db.exec("INSERT INTO ciphers(id, user_id, type, data, created_at, updated_at) VALUES('c1', 'u1', 1, '{}', 'now', 'now')");
  db.exec("INSERT INTO collection_items(collection_id, cipher_id) VALUES('col-1', 'c1')");

  db.exec("DELETE FROM organizations WHERE id = 'org-1'");

  // The link and the collection go; the cipher itself survives.
  assert.equal((db.prepare('SELECT COUNT(*) AS n FROM collections').get() as any).n, 0);
  assert.equal((db.prepare('SELECT COUNT(*) AS n FROM collection_items').get() as any).n, 0);
  assert.equal((db.prepare('SELECT COUNT(*) AS n FROM ciphers').get() as any).n, 1);
  db.close();
});

// The runtime bootstrap and the init migration are two sources for one schema;
// the header of storage-schema.ts requires they stay in step. Nothing else
// enforces it, so compare the shapes they actually produce.
test('the init migration and the runtime bootstrap produce the same schema', () => {
  const bootstrapped = new DatabaseSync(':memory:');
  // storage.ts creates `config` outside SCHEMA_STATEMENTS, before the bootstrap runs.
  bootstrapped.exec('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
  applySchema(bootstrapped);

  const migrated = new DatabaseSync(':memory:');
  migrated.exec(readFileSync('migrations/0001_init.sql', 'utf8'));

  const shape = (db: DatabaseSync): Map<string, string[]> => {
    const out = new Map<string, string[]>();
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
      .all() as Array<{ name: string }>;
    for (const table of tables) {
      const columns = (db.prepare(`PRAGMA table_info(${table.name})`).all() as Array<{ name: string }>)
        .map((column) => String(column.name))
        .sort();
      out.set(String(table.name), columns);
    }
    return out;
  };

  const fromBootstrap = shape(bootstrapped);
  const fromMigration = shape(migrated);

  assert.deepEqual(
    Array.from(fromBootstrap.keys()).sort(),
    Array.from(fromMigration.keys()).sort(),
    'table sets differ between the bootstrap and the init migration'
  );
  for (const [table, columns] of fromBootstrap) {
    assert.deepEqual(columns, fromMigration.get(table), `columns differ for ${table}`);
  }

  bootstrapped.close();
  migrated.close();
});

// Owner-scoped bulk SQL must skip org ciphers: the row's user_id is only the
// author, who may have left the organization.
test('bulk mutations leave organization ciphers untouched', () => {
  const db = freshDb();
  db.exec("INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES('u1', 'a@b.c', 'h', 'k', 0, 600000, 's', 'now', 'now')");
  db.exec("INSERT INTO organizations(id, name, owner_id, created_at, updated_at) VALUES('org-1', 'Acme', 'u1', 'now', 'now')");
  db.exec("INSERT INTO collections(id, organization_id, name, created_at, updated_at) VALUES('col-1', 'org-1', 'enc', 'now', 'now')");
  // Org cipher authored by u1 (in a collection) and an unassigned org cipher (JSON marker only).
  db.exec("INSERT INTO ciphers(id, user_id, type, data, created_at, updated_at) VALUES('org-a', 'u1', 1, '{}', 'now', 'now')");
  db.exec("INSERT INTO collection_items(collection_id, cipher_id) VALUES('col-1', 'org-a')");
  db.exec("INSERT INTO ciphers(id, user_id, type, data, created_at, updated_at) VALUES('org-b', 'u1', 1, '{\"organizationId\":\"org-1\"}', 'now', 'now')");
  db.exec("INSERT INTO ciphers(id, user_id, type, data, created_at, updated_at) VALUES('personal', 'u1', 1, '{}', 'now', 'now')");

  db.exec(`DELETE FROM ciphers WHERE user_id = 'u1' AND id IN ('org-a','org-b','personal') ${PERSONAL_CIPHER_ONLY}`);

  const remaining = db.prepare('SELECT id FROM ciphers ORDER BY id').all().map((row: any) => String(row.id));
  // Only the personal cipher is deleted; both org ciphers survive.
  assert.deepEqual(remaining, ['org-a', 'org-b']);
  db.close();
});
