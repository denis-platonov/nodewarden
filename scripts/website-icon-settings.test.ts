import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { handleWebsiteIcon } from '../src/handlers/website-icons';
import { StorageService } from '../src/services/storage';
import {
  WEBSITE_ICON_SETTINGS_CACHE_TTL_MS,
  WEBSITE_ICON_SETTINGS_KEY,
  areThirdPartyIconSourcesAllowed,
  describeWebsiteIconSettings,
  getWebsiteIconSettings,
  normalizeWebsiteIconSettings,
  resetWebsiteIconSettingsCache,
  saveWebsiteIconSettings,
} from '../src/services/website-icon-settings';
import type { Env } from '../src/types';

const DIRECT_URLS = [
  'https://example.com/favicon.ico',
  'https://example.com/favicon.png',
  'https://example.com/apple-touch-icon.png',
];
const FAVICON_IM_URL = 'https://favicon.im/zh/example.com?larger=true&throw-error-on-404=true';
const BITWARDEN_URL = 'https://icons.bitwarden.net/example.com/icon.png';
const ALL_URLS = [...DIRECT_URLS, FAVICON_IM_URL, BITWARDEN_URL];

/**
 * The config table, and a count of every statement that actually reached it.
 * The count is the point of most of this file: the icon path made no D1 query
 * at all before this setting existed and must not start making one per icon.
 */
type FakeDb = {
  db: D1Database;
  rows: Map<string, string>;
  reads: number;
  failReads: boolean;
};

function fakeConfigDb(initial: Record<string, string> = {}): FakeDb {
  const state: FakeDb = {
    rows: new Map(Object.entries(initial)),
    reads: 0,
    failReads: false,
    db: null as unknown as D1Database,
  };

  state.db = {
    prepare(sql: string) {
      return {
        bind(...args: unknown[]) {
          return {
            async first() {
              if (!/^SELECT value FROM config/i.test(sql)) return null;
              state.reads += 1;
              if (state.failReads) throw new Error('D1 unavailable');
              const value = state.rows.get(String(args[0]));
              return value === undefined ? null : { value };
            },
            async run() {
              if (/^INSERT INTO config/i.test(sql)) {
                state.rows.set(String(args[0]), String(args[1]));
              }
              return { success: true };
            },
          };
        },
      };
    },
  } as unknown as D1Database;

  return state;
}

function envWith(fake: FakeDb, extra: Partial<Env> = {}): Env {
  return { DB: fake.db, ...extra } as Env;
}

function stored(thirdPartySourcesEnabled: boolean): Record<string, string> {
  return { [WEBSITE_ICON_SETTINGS_KEY]: JSON.stringify({ thirdPartySourcesEnabled }) };
}

function pngResponse(byteLength = 64): Response {
  return new Response(new Uint8Array(byteLength), {
    status: 200,
    headers: { 'Content-Type': 'image/png' },
  });
}

function notFound(): Response {
  return new Response(null, { status: 404 });
}

async function withStubbedFetch<T>(
  stub: (url: string) => Response | Promise<Response>,
  run: () => Promise<T>
): Promise<{ result: T; urls: string[] }> {
  const originalFetch = globalThis.fetch;
  const urls: string[] = [];
  globalThis.fetch = (async (input: unknown) => {
    const url = String(input);
    urls.push(url);
    return await stub(url);
  }) as typeof fetch;
  try {
    return { result: await run(), urls };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test.beforeEach(() => {
  resetWebsiteIconSettingsCache();
});

test('the stored setting turned off keeps the lookup between this server and the site', async () => {
  const fake = fakeConfigDb(stored(false));
  const { urls, result } = await withStubbedFetch(
    () => notFound(),
    () => handleWebsiteIcon(envWith(fake), 'example.com')
  );

  assert.deepEqual(urls, DIRECT_URLS);
  assert.equal(result.headers.get('Content-Type'), 'image/svg+xml; charset=utf-8');
});

test('the stored setting turned on is what the server already did', async () => {
  const fake = fakeConfigDb(stored(true));
  const { urls } = await withStubbedFetch(
    () => notFound(),
    () => handleWebsiteIcon(envWith(fake), 'example.com')
  );

  assert.deepEqual(urls, ALL_URLS);
});

test('neither control set leaves the third parties allowed, so an upgrade changes nothing', async () => {
  const fake = fakeConfigDb();
  const { urls } = await withStubbedFetch(
    () => notFound(),
    () => handleWebsiteIcon(envWith(fake), 'example.com')
  );

  assert.deepEqual(urls, ALL_URLS);
  assert.equal(await areThirdPartyIconSourcesAllowed(envWith(fakeConfigDb())), true);
  // A deployment with no database bound at all is the same default.
  assert.equal(await areThirdPartyIconSourcesAllowed({} as Env), true);
});

test('DISABLE_THIRD_PARTY_ICONS=1 overrides a stored setting that allows them', async () => {
  const fake = fakeConfigDb(stored(true));
  const env = envWith(fake, { DISABLE_THIRD_PARTY_ICONS: '1' });

  const { urls } = await withStubbedFetch(
    () => notFound(),
    () => handleWebsiteIcon(env, 'example.com')
  );

  assert.deepEqual(urls, DIRECT_URLS);
  // The row still says "allowed"; the variable is simply the harder guarantee,
  // and the row is never even read.
  assert.equal(await getWebsiteIconSettings(new StorageService(fake.db)).then((s) => s.thirdPartySourcesEnabled), true);
  assert.equal(await areThirdPartyIconSourcesAllowed(env), false);
});

test('a stored setting cannot be undone by the absence of the variable either way round', async () => {
  const permissiveEnvOff = envWith(fakeConfigDb(stored(false)));
  assert.equal(await areThirdPartyIconSourcesAllowed(permissiveEnvOff), false);

  resetWebsiteIconSettingsCache();
  const permissiveEnvOn = envWith(fakeConfigDb(stored(true)), { DISABLE_THIRD_PARTY_ICONS: '0' });
  assert.equal(await areThirdPartyIconSourcesAllowed(permissiveEnvOn), true);
});

test('an icon the site serves itself costs no config read at all', async () => {
  const fake = fakeConfigDb(stored(true));
  const { urls, result } = await withStubbedFetch(
    (url) => (url === DIRECT_URLS[0] ? pngResponse() : notFound()),
    () => handleWebsiteIcon(envWith(fake), 'example.com')
  );

  assert.deepEqual(urls, [DIRECT_URLS[0]]);
  assert.equal(result.status, 200);
  assert.equal(fake.reads, 0);
});

test('many misses in one isolate share a single config read', async () => {
  const fake = fakeConfigDb(stored(true));
  const env = envWith(fake);

  for (let i = 0; i < 20; i += 1) {
    await withStubbedFetch(() => notFound(), () => handleWebsiteIcon(env, 'example.com'));
  }

  assert.equal(fake.reads, 1);
});

test('the cached answer is not served past its stated window', async () => {
  const fake = fakeConfigDb(stored(true));
  const env = envWith(fake);
  const start = Date.now();

  assert.equal(await areThirdPartyIconSourcesAllowed(env, start), true);
  assert.equal(fake.reads, 1);

  // Somebody else's isolate writes the row.
  fake.rows.set(WEBSITE_ICON_SETTINGS_KEY, JSON.stringify({ thirdPartySourcesEnabled: false }));

  // Inside the window this isolate is allowed to be stale, and is.
  assert.equal(await areThirdPartyIconSourcesAllowed(env, start + WEBSITE_ICON_SETTINGS_CACHE_TTL_MS - 1), true);
  assert.equal(fake.reads, 1);

  // One millisecond past it, it must go and look again.
  assert.equal(await areThirdPartyIconSourcesAllowed(env, start + WEBSITE_ICON_SETTINGS_CACHE_TTL_MS), false);
  assert.equal(fake.reads, 2);
});

test('saving takes effect at once in the isolate that saved, without another read', async () => {
  const fake = fakeConfigDb(stored(true));
  const env = envWith(fake);
  const storage = new StorageService(fake.db);

  assert.equal(await areThirdPartyIconSourcesAllowed(env), true);
  const readsAfterFirstLook = fake.reads;

  await saveWebsiteIconSettings(storage, { thirdPartySourcesEnabled: false });

  const { urls } = await withStubbedFetch(
    () => notFound(),
    () => handleWebsiteIcon(env, 'example.com')
  );
  assert.deepEqual(urls, DIRECT_URLS);
  assert.equal(fake.reads, readsAfterFirstLook);
});

test('a failed config read does not re-enable third parties this isolate had switched off', async () => {
  const fake = fakeConfigDb(stored(false));
  const env = envWith(fake);
  const start = Date.now();

  assert.equal(await areThirdPartyIconSourcesAllowed(env, start), false);

  fake.failReads = true;
  assert.equal(
    await areThirdPartyIconSourcesAllowed(env, start + WEBSITE_ICON_SETTINGS_CACHE_TTL_MS),
    false
  );

  // And a process that never managed a read falls back to the documented default.
  resetWebsiteIconSettingsCache();
  const cold = fakeConfigDb();
  cold.failReads = true;
  assert.equal(await areThirdPartyIconSourcesAllowed(envWith(cold)), true);
});

test('a corrupt or partial row normalizes rather than throwing', async () => {
  assert.equal(normalizeWebsiteIconSettings(undefined).thirdPartySourcesEnabled, true);
  assert.equal(normalizeWebsiteIconSettings({}).thirdPartySourcesEnabled, true);
  assert.equal(normalizeWebsiteIconSettings('nonsense').thirdPartySourcesEnabled, true);
  assert.equal(normalizeWebsiteIconSettings({ thirdPartySourcesEnabled: false }).thirdPartySourcesEnabled, false);
  assert.equal(normalizeWebsiteIconSettings({ thirdPartySourcesEnabled: '0' }).thirdPartySourcesEnabled, false);
  assert.equal(normalizeWebsiteIconSettings({ thirdPartySourcesEnabled: 'false' }).thirdPartySourcesEnabled, false);
  assert.equal(normalizeWebsiteIconSettings({ thirdPartySourcesEnabled: '1' }).thirdPartySourcesEnabled, true);

  const fake = fakeConfigDb({ [WEBSITE_ICON_SETTINGS_KEY]: '{not json' });
  const settings = await getWebsiteIconSettings(new StorageService(fake.db));
  assert.equal(settings.thirdPartySourcesEnabled, true);
});

test('the endpoint reports the stored value and what is actually in force', () => {
  const allowed = { thirdPartySourcesEnabled: true };

  assert.deepEqual(describeWebsiteIconSettings({} as Env, allowed), {
    thirdPartySourcesEnabled: true,
    disabledByEnv: false,
    effectiveThirdPartySourcesEnabled: true,
  });

  // The row still says "allowed" and is stored as such; the variable simply
  // wins, and the response has to admit that rather than echoing the toggle.
  assert.deepEqual(
    describeWebsiteIconSettings({ DISABLE_THIRD_PARTY_ICONS: '1' } as Env, allowed),
    {
      thirdPartySourcesEnabled: true,
      disabledByEnv: true,
      effectiveThirdPartySourcesEnabled: false,
    }
  );

  // A row that says "off" needs no variable to be in force.
  assert.deepEqual(describeWebsiteIconSettings({} as Env, { thirdPartySourcesEnabled: false }), {
    thirdPartySourcesEnabled: false,
    disabledByEnv: false,
    effectiveThirdPartySourcesEnabled: false,
  });

  // Anything but exactly "1" is not the override.
  for (const value of ['', '0', 'true', 'yes', ' 1 x']) {
    assert.equal(
      describeWebsiteIconSettings({ DISABLE_THIRD_PARTY_ICONS: value } as Env, allowed).disabledByEnv,
      false,
      `DISABLE_THIRD_PARTY_ICONS=${JSON.stringify(value)} is not the override`
    );
  }
  assert.equal(
    describeWebsiteIconSettings({ DISABLE_THIRD_PARTY_ICONS: ' 1 ' } as Env, allowed).disabledByEnv,
    true
  );
});

test('a saved setting round-trips through the config row', async () => {
  const fake = fakeConfigDb();
  const storage = new StorageService(fake.db);

  const saved = await saveWebsiteIconSettings(storage, { thirdPartySourcesEnabled: false });
  assert.deepEqual(saved, { thirdPartySourcesEnabled: false });
  assert.equal(
    fake.rows.get(WEBSITE_ICON_SETTINGS_KEY),
    JSON.stringify({ thirdPartySourcesEnabled: false })
  );
  assert.deepEqual(await getWebsiteIconSettings(storage), { thirdPartySourcesEnabled: false });

  await saveWebsiteIconSettings(storage, { thirdPartySourcesEnabled: true });
  assert.deepEqual(await getWebsiteIconSettings(storage), { thirdPartySourcesEnabled: true });
});

/**
 * The admin handlers and the route table cannot be imported here: both chains
 * reach a `cloudflare:workers` import Node cannot load. What they contribute
 * beyond the functions tested above is wiring, and wiring is what a missing
 * line silently breaks - a path absent from isKnownAdminPath returns null and
 * falls through to the 404 handler, and a handler that forgets isAdmin hands
 * a runtime setting to every logged-in user. Both are asserted as source, the
 * way scripts/webauthn-connector-headers.test.ts already does.
 */
test('the handlers are admin-gated and audited', async () => {
  const source = await readFile(new URL('../src/handlers/admin.ts', import.meta.url), 'utf8');
  const handlers = source.split('export async function handleAdmin');
  for (const name of ['GetWebsiteIconSettings', 'UpdateWebsiteIconSettings']) {
    const body = handlers.find((chunk) => chunk.startsWith(name));
    assert.ok(body, `${name} is defined`);
    assert.match(body, /if \(!isAdmin\(actorUser\)\) \{\s+return errorResponse\('Forbidden', 403\);/);
  }
  assert.match(source, /writeAuditLog\(storage, actorUser\.id, 'admin\.icons\.settings\.update'/);
  assert.match(source, /return errorResponse\('Invalid JSON', 400\);/);
});

test('the endpoint is wired into the admin router, allowlist included', async () => {
  const source = await readFile(new URL('../src/router-admin.ts', import.meta.url), 'utf8');
  assert.match(source, /path === '\/api\/admin\/icons\/settings' \|\|/);
  assert.match(source, /if \(path === '\/api\/admin\/icons\/settings'\) \{/);
  assert.match(source, /handleAdminGetWebsiteIconSettings\(request, env, actorUser\)/);
  assert.match(source, /handleAdminUpdateWebsiteIconSettings\(request, env, actorUser\)/);
});
