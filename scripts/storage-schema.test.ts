import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { SCHEMA_STATEMENTS } from '../src/services/storage-schema';
import { PERSONAL_CIPHER_ONLY } from '../src/services/storage-cipher-repo';
import {
  ATTACHMENTS_BY_USER_SQL,
  ATTACHMENT_UPSERT_SQL,
  getAttachmentsForUserAndCiphers,
} from '../src/services/storage-attachment-repo';

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

// The user's attachments used to be found by joining into ciphers, which the
// planner drives from the ciphers side: one index row per cipher in the vault
// on every sync, even for a vault holding no attachments at all. The
// denormalised user_id is what keeps that lookup proportional to the answer.
test('listing the attachments for a user reads attachments only', () => {
  const db = freshDb();
  db.exec("INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES('u1', 'a@b.c', 'h', 'k', 0, 600000, 's', 'now', 'now')");
  db.exec("INSERT INTO ciphers(id, user_id, type, data, created_at, updated_at) VALUES('c1', 'u1', 1, '{}', 'now', 'now')");

  const plan = db
    .prepare(`EXPLAIN QUERY PLAN ${ATTACHMENTS_BY_USER_SQL}`)
    .all()
    .map((row: any) => String(row.detail));

  assert.equal(plan.length, 1, `expected a single lookup, got ${JSON.stringify(plan)}`);
  assert.match(plan[0], /idx_attachments_user/);
  // Nothing may reach ciphers: that is the row count this fix removed.
  for (const step of plan) {
    assert.equal(/ciphers/.test(step), false, `plan still reads ciphers: ${step}`);
  }
  db.close();
});

test('saving an attachment copies the owning cipher user onto the row', () => {
  const db = freshDb();
  db.exec("INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES('u1', 'a@b.c', 'h', 'k', 0, 600000, 's', 'now', 'now')");
  db.exec("INSERT INTO ciphers(id, user_id, type, data, created_at, updated_at) VALUES('c1', 'u1', 1, '{}', 'now', 'now')");

  // The caller never supplies user_id; the statement reads it off the cipher.
  db.prepare(ATTACHMENT_UPSERT_SQL).run('a1', 'c1', 'c1', 'enc-name', 10, '10 Bytes', 'enc-key');

  const row: any = db.prepare(`${ATTACHMENTS_BY_USER_SQL.replace('?', "'u1'")}`).get();
  assert.equal(row.id, 'a1');
  assert.equal(row.cipher_id, 'c1');
  db.close();
});

test('the bootstrap backfills user_id onto attachments written before the column', () => {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  // The pre-column shape, as an installed instance would have it.
  db.exec("CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, master_password_hint TEXT, master_password_hash TEXT NOT NULL, key TEXT NOT NULL, private_key TEXT, public_key TEXT, kdf_type INTEGER NOT NULL, kdf_iterations INTEGER NOT NULL, kdf_memory INTEGER, kdf_parallelism INTEGER, security_stamp TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active', verify_devices INTEGER NOT NULL DEFAULT 0, totp_secret TEXT, totp_recovery_code TEXT, yubikey_key1 TEXT, yubikey_key2 TEXT, yubikey_key3 TEXT, yubikey_key4 TEXT, yubikey_key5 TEXT, yubikey_nfc INTEGER NOT NULL DEFAULT 0, api_key TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)");
  db.exec("CREATE TABLE ciphers (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, type INTEGER NOT NULL, folder_id TEXT, name TEXT, notes TEXT, favorite INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL, reprompt INTEGER, key TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, archived_at TEXT, deleted_at TEXT, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)");
  db.exec('CREATE TABLE attachments (id TEXT PRIMARY KEY, cipher_id TEXT NOT NULL, file_name TEXT NOT NULL, size INTEGER NOT NULL, size_name TEXT NOT NULL, key TEXT, FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE)');
  db.exec("INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES('u1', 'a@b.c', 'h', 'k', 0, 600000, 's', 'now', 'now')");
  db.exec("INSERT INTO ciphers(id, user_id, type, data, created_at, updated_at) VALUES('c1', 'u1', 1, '{}', 'now', 'now')");
  db.exec("INSERT INTO attachments(id, cipher_id, file_name, size, size_name) VALUES('a1', 'c1', 'enc-name', 10, '10 Bytes')");

  applySchema(db);

  const row: any = db.prepare("SELECT user_id FROM attachments WHERE id = 'a1'").get();
  assert.equal(row.user_id, 'u1');
  db.close();
});

test('a sync with no org ciphers asks for attachments exactly once', async () => {
  const db = freshDb();
  db.exec("INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES('u1', 'a@b.c', 'h', 'k', 0, 600000, 's', 'now', 'now')");
  db.exec("INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES('u2', 'd@e.f', 'h', 'k', 0, 600000, 's', 'now', 'now')");
  // A vault big enough that the old path would have batched it, and with no
  // attachments at all -- the case that was costing one index seek per cipher
  // on every sync to discover there was nothing to find.
  for (let i = 0; i < 250; i++) {
    db.exec(`INSERT INTO ciphers(id, user_id, type, data, created_at, updated_at) VALUES('c${i}', 'u1', 1, '{}', 'now', 'now')`);
  }

  const { db: spy, queries } = countingDb(db);
  const grouped = await getAttachmentsForUserAndCiphers(spy as any, () => 100, 'u1', []);

  assert.equal(grouped.size, 0);
  assert.equal(
    queries.length,
    1,
    `expected one query for a vault with no org ciphers, got ${JSON.stringify(queries)}`
  );
  assert.match(queries[0], /user_id = \?/);
  assert.equal(/cipher_id IN/.test(queries[0]), false, queries[0]);
  db.close();
});

test('org ciphers owned by somebody else still bring their attachments back', async () => {
  const db = freshDb();
  db.exec("INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES('u1', 'a@b.c', 'h', 'k', 0, 600000, 's', 'now', 'now')");
  db.exec("INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES('u2', 'd@e.f', 'h', 'k', 0, 600000, 's', 'now', 'now')");
  db.exec("INSERT INTO ciphers(id, user_id, type, data, created_at, updated_at) VALUES('mine', 'u1', 1, '{}', 'now', 'now')");
  // Owned by u2, reachable by u1 through a collection. `attachments.user_id`
  // is the OWNER's, so the by-user query cannot see this one -- which is the
  // whole reason the org ids are still asked for by cipher.
  db.exec("INSERT INTO ciphers(id, user_id, type, data, created_at, updated_at) VALUES('theirs', 'u2', 1, '{}', 'now', 'now')");
  db.prepare(ATTACHMENT_UPSERT_SQL).run('a-mine', 'mine', 'mine', 'n', 1, '1 Byte', 'k');
  db.prepare(ATTACHMENT_UPSERT_SQL).run('a-theirs', 'theirs', 'theirs', 'n', 1, '1 Byte', 'k');

  const grouped = await getAttachmentsForUserAndCiphers(
    countingDb(db).db as any,
    () => 100,
    'u1',
    ['theirs']
  );

  assert.deepEqual(grouped.get('mine')?.map((a) => a.id), ['a-mine']);
  assert.deepEqual(
    grouped.get('theirs')?.map((a) => a.id),
    ['a-theirs'],
    'an org cipher owned by another user lost its attachment'
  );
  db.close();
});

test('an org cipher the user owns is not listed twice', async () => {
  const db = freshDb();
  db.exec("INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES('u1', 'a@b.c', 'h', 'k', 0, 600000, 's', 'now', 'now')");
  db.exec("INSERT INTO ciphers(id, user_id, type, data, created_at, updated_at) VALUES('c1', 'u1', 1, '{}', 'now', 'now')");
  db.prepare(ATTACHMENT_UPSERT_SQL).run('a1', 'c1', 'c1', 'n', 1, '1 Byte', 'k');

  // The caller passes org ids without checking who owns them, which is what
  // makes it safe to be careless there: this id comes back from BOTH queries.
  const grouped = await getAttachmentsForUserAndCiphers(
    countingDb(db).db as any,
    () => 100,
    'u1',
    ['c1']
  );

  assert.deepEqual(
    grouped.get('c1')?.map((a) => a.id),
    ['a1'],
    'the attachment was counted once per query rather than once per attachment'
  );
  db.close();
});

/**
 * `node:sqlite` in D1's clothing: `prepare().bind().all()` returning
 * `{ results }`, which is the shape the repo is written against.
 *
 * It also records the SQL, because one of these tests makes a claim about the
 * NUMBER of queries issued and no assertion on the returned rows can reach
 * that.
 */
function countingDb(db: any): { db: any; queries: string[] } {
  const queries: string[] = [];
  return {
    queries,
    db: {
      prepare(sql: string) {
        queries.push(sql);
        const stmt = db.prepare(sql);
        return {
          bind(...args: any[]) {
            return {
              async all() {
                return { results: stmt.all(...args) };
              },
            };
          },
        };
      },
    },
  };
}
