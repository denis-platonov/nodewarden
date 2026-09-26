import assert from 'node:assert/strict';
import test from 'node:test';

import { LIMITS } from '../src/config/limits';
import {
  handleWebsiteIcon,
  isInertSvgIcon,
  isPublicIconHost,
  normalizeIconHost,
  resolveDirectIconRedirect,
} from '../src/handlers/website-icons';
import type { Env } from '../src/types';

const env = {} as Env;
const noThirdPartyEnv = { DISABLE_THIRD_PARTY_ICONS: '1' } as Env;

const DIRECT_URLS = [
  'https://example.com/favicon.ico',
  'https://example.com/favicon.png',
  'https://example.com/apple-touch-icon.png',
  'https://example.com/favicon.svg',
];
const SVG_URL = DIRECT_URLS[3];
const FAVICON_IM_URL = 'https://favicon.im/zh/example.com?larger=true&throw-error-on-404=true';
const BITWARDEN_URL = 'https://icons.bitwarden.net/example.com/icon.png';

type FetchStub = (url: string) => Response | Promise<Response>;

function pngResponse(byteLength = 64, headers: Record<string, string> = {}): Response {
  return new Response(new Uint8Array(byteLength), {
    status: 200,
    headers: { 'Content-Type': 'image/png', ...headers },
  });
}

const SITE_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#c8431f"/></svg>';

function svgResponse(body: string): Response {
  return new Response(body, { status: 200, headers: { 'Content-Type': 'image/svg+xml' } });
}

function notFound(): Response {
  return new Response(null, { status: 404 });
}

/** Runs `run` with a stubbed global fetch and reports every URL it asked for. */
async function withStubbedFetch<T>(
  stub: FetchStub,
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

test('the site itself is asked first, then favicon.im, then icons.bitwarden.net', async () => {
  const { result, urls } = await withStubbedFetch(
    () => notFound(),
    () => handleWebsiteIcon(env, 'example.com')
  );

  assert.deepEqual(urls, [...DIRECT_URLS, FAVICON_IM_URL, BITWARDEN_URL]);
  assert.equal(result.status, 200);
});

test('an icon served by the origin never reaches a third party', async () => {
  const { result, urls } = await withStubbedFetch(
    (url) => (url === DIRECT_URLS[0] ? pngResponse() : notFound()),
    () => handleWebsiteIcon(env, 'example.com')
  );

  assert.deepEqual(urls, [DIRECT_URLS[0]]);
  assert.equal(result.status, 200);
  assert.equal(result.headers.get('Content-Type'), 'image/png');
  assert.equal(
    result.headers.get('Cache-Control'),
    `public, max-age=${LIMITS.cache.iconTtlSeconds}, immutable`
  );
  assert.equal((await result.arrayBuffer()).byteLength, 64);
});

test('a 404 on one direct path moves on to the next one, not off the host', async () => {
  const { result, urls } = await withStubbedFetch(
    (url) => (url === DIRECT_URLS[2] ? pngResponse() : notFound()),
    () => handleWebsiteIcon(env, 'example.com')
  );

  assert.deepEqual(urls, DIRECT_URLS.slice(0, 3));
  assert.equal(result.status, 200);
});

test("a site whose only icon is /favicon.svg gets that icon, sandboxed", async () => {
  // https://23000268.xyz/: `<link rel="icon" href="/favicon.svg">`, and the
  // raster paths redirect to a login page.
  const { result, urls } = await withStubbedFetch(
    (url) => (url === SVG_URL ? svgResponse(SITE_SVG) : notFound()),
    () => handleWebsiteIcon(env, 'example.com')
  );

  assert.deepEqual(urls, DIRECT_URLS);
  assert.equal(result.status, 200);
  assert.equal(result.headers.get('Content-Type'), 'image/svg+xml');
  assert.match(String(result.headers.get('Content-Security-Policy')), /\bsandbox\b/);
  assert.match(String(result.headers.get('Content-Security-Policy')), /default-src 'none'/);
  assert.equal(await result.text(), SITE_SVG);
});

test('an SVG that can do anything but draw is refused', async () => {
  for (const active of [
    '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
    '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>',
    '<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><rect/></a></svg>',
    '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div/></foreignObject></svg>',
    '<!doctype html><html><body>not an icon</body></html>',
  ]) {
    const { urls } = await withStubbedFetch(
      (url) => (url === SVG_URL ? svgResponse(active) : notFound()),
      () => handleWebsiteIcon(env, 'example.com')
    );
    assert.deepEqual(urls, [...DIRECT_URLS, FAVICON_IM_URL, BITWARDEN_URL], active);
  }
});

test('an SVG is accepted from the site only, never from a third party', async () => {
  const { result } = await withStubbedFetch(
    (url) => (url === FAVICON_IM_URL ? svgResponse(SITE_SVG) : notFound()),
    () => handleWebsiteIcon(env, 'example.com')
  );
  assert.notEqual(result.headers.get('Content-Type'), 'image/svg+xml');
});

test('the inert-SVG rule, by itself', () => {
  const bytes = (text: string) => new TextEncoder().encode(text).buffer as ArrayBuffer;
  assert.ok(isInertSvgIcon(bytes(SITE_SVG)));
  assert.ok(isInertSvgIcon(bytes(`\uFEFF<?xml version="1.0"?>\n<!-- icon -->\n${SITE_SVG}`)));
  assert.ok(!isInertSvgIcon(bytes('<html><svg></svg></html>')), 'an SVG inside HTML is not an SVG');
  assert.ok(!isInertSvgIcon(bytes('<svg><script/></svg>')));
  assert.ok(!isInertSvgIcon(bytes('<svg ONCLICK="x()"></svg>')), 'event handlers are refused in any case');
});

test('a host that does not answer costs one timeout, not three', async () => {
  const { urls } = await withStubbedFetch(
    (url) => {
      if (url.startsWith('https://example.com/')) throw new TypeError('fetch failed');
      return notFound();
    },
    () => handleWebsiteIcon(env, 'example.com')
  );

  assert.deepEqual(urls, [DIRECT_URLS[0], FAVICON_IM_URL, BITWARDEN_URL]);
});

test('a single-page app serving index.html for /favicon.ico is not an icon', async () => {
  const { urls } = await withStubbedFetch(
    (url) =>
      url === DIRECT_URLS[0]
        ? new Response('<!doctype html>', { status: 200, headers: { 'Content-Type': 'text/html' } })
        : notFound(),
    () => handleWebsiteIcon(env, 'example.com')
  );

  assert.deepEqual(urls, [...DIRECT_URLS, FAVICON_IM_URL, BITWARDEN_URL]);
});

test('the byte cap applies to the origin, by header and by body', async () => {
  const declared = await withStubbedFetch(
    (url) =>
      url === DIRECT_URLS[0]
        ? pngResponse(64, { 'Content-Length': String(4 * 1024 * 1024) })
        : notFound(),
    () => handleWebsiteIcon(noThirdPartyEnv, 'example.com')
  );
  assert.deepEqual(declared.urls, DIRECT_URLS);
  assert.equal(declared.result.headers.get('Content-Type'), 'image/svg+xml; charset=utf-8');

  const streamed = await withStubbedFetch(
    (url) => {
      if (url !== DIRECT_URLS[0]) return notFound();
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          for (let sent = 0; sent < 512 * 1024; sent += 64 * 1024) {
            controller.enqueue(new Uint8Array(64 * 1024));
          }
          controller.close();
        },
      });
      return new Response(stream, { status: 200, headers: { 'Content-Type': 'image/png' } });
    },
    () => handleWebsiteIcon(noThirdPartyEnv, 'example.com')
  );
  assert.deepEqual(streamed.urls, DIRECT_URLS);
  assert.equal(streamed.result.headers.get('Content-Type'), 'image/svg+xml; charset=utf-8');
});

test('no direct fetch is made to an address or a name off the public internet', async () => {
  const offLimits = [
    '127.0.0.1',
    '192.168.1.1',
    '10.0.0.5',
    '172.16.0.1',
    '169.254.169.254',
    '8.8.8.8',
    '[::1]',
    '[::ffff:7f00:1]',
    'localhost',
    'router',
    'nas.local',
    'db.internal',
    'printer.home.arpa',
    'service.corp',
    'thing.lan',
    'site.test',
    'abcdefg.onion',
  ];

  for (const host of offLimits) {
    const { urls } = await withStubbedFetch(
      () => notFound(),
      () => handleWebsiteIcon(env, host)
    );
    assert.ok(
      !urls.some((url) => url.startsWith(`https://${host}/`)),
      `${host} must never be fetched directly, got ${JSON.stringify(urls)}`
    );
  }
});

test('with the third parties off, an off-limits host produces no request at all', async () => {
  const { result, urls } = await withStubbedFetch(
    () => notFound(),
    () => handleWebsiteIcon(noThirdPartyEnv, '169.254.169.254')
  );

  assert.deepEqual(urls, []);
  assert.equal(result.status, 200);
  assert.equal(result.headers.get('Content-Type'), 'image/svg+xml; charset=utf-8');
});

test('an address spelled around the host check never becomes a host', () => {
  for (const host of ['2130706433', '0x7f.1', '127.1', '[::ffff:127.0.0.1]', 'host:8080', 'user@host']) {
    assert.equal(normalizeIconHost(host), null, host);
  }
  assert.equal(normalizeIconHost('EXAMPLE.com.'), 'example.com');
  assert.equal(isPublicIconHost('example.com'), true);
  assert.equal(isPublicIconHost('xn--r8jz45g.jp'), true);
});

test('a redirect off the public internet is refused, not followed', async () => {
  for (const location of [
    'http://169.254.169.254/',
    '//192.168.0.1/icon.png',
    'https://127.0.0.1/icon.png',
    'https://localhost/icon.png',
    'http://example.com/icon.png',
    'https://cdn.example.net:8443/icon.png',
  ]) {
    const { urls } = await withStubbedFetch(
      (url) =>
        url === DIRECT_URLS[0]
          ? new Response(null, { status: 302, headers: { Location: location } })
          : notFound(),
      () => handleWebsiteIcon(noThirdPartyEnv, 'example.com')
    );
    assert.deepEqual(urls, DIRECT_URLS, `refused redirect to ${location}`);
  }
});

test('a redirect to another public https host is followed', async () => {
  const { result, urls } = await withStubbedFetch(
    (url) => {
      if (url === DIRECT_URLS[0]) {
        return new Response(null, {
          status: 301,
          headers: { Location: 'https://cdn.example.net/icon.png' },
        });
      }
      if (url === 'https://cdn.example.net/icon.png') return pngResponse();
      return notFound();
    },
    () => handleWebsiteIcon(env, 'example.com')
  );

  assert.deepEqual(urls, [DIRECT_URLS[0], 'https://cdn.example.net/icon.png']);
  assert.equal(result.status, 200);
  assert.equal(result.headers.get('Content-Type'), 'image/png');
});

test('a redirect loop is bounded rather than followed forever', async () => {
  const { urls } = await withStubbedFetch(
    (url) =>
      url.startsWith('https://example.com/favicon.ico')
        ? new Response(null, { status: 302, headers: { Location: '/favicon.ico?hop' } })
        : notFound(),
    () => handleWebsiteIcon(noThirdPartyEnv, 'example.com')
  );

  assert.ok(urls.length <= 8, `bounded hops, got ${urls.length}`);
});

test('every redirect rule is decided in one place', () => {
  const from = 'https://example.com/favicon.ico';
  assert.equal(resolveDirectIconRedirect(from, null), null);
  assert.equal(resolveDirectIconRedirect(from, 'http://example.com/i.png'), null);
  assert.equal(resolveDirectIconRedirect(from, 'https://example.com:8443/i.png'), null);
  assert.equal(resolveDirectIconRedirect(from, 'https://user:pw@example.com/i.png'), null);
  assert.equal(resolveDirectIconRedirect(from, 'https://10.1.2.3/i.png'), null);
  assert.equal(resolveDirectIconRedirect(from, 'https://box.internal/i.png'), null);
  assert.equal(
    resolveDirectIconRedirect(from, '/static/icon.png'),
    'https://example.com/static/icon.png'
  );
  assert.equal(
    resolveDirectIconRedirect(from, 'https://cdn.example.net/i.png'),
    'https://cdn.example.net/i.png'
  );
});

test('a miss is cached for minutes, not for a week', async () => {
  const placeholder = await withStubbedFetch(
    () => notFound(),
    () => handleWebsiteIcon(env, 'example.com')
  );
  assert.equal(placeholder.result.status, 200);
  assert.equal(
    placeholder.result.headers.get('Cache-Control'),
    `public, max-age=${LIMITS.cache.iconFallbackTtlSeconds}`
  );
  assert.doesNotMatch(placeholder.result.headers.get('Cache-Control') || '', /immutable/);
  assert.ok(LIMITS.cache.iconFallbackTtlSeconds < LIMITS.cache.iconTtlSeconds);

  const missing = await withStubbedFetch(
    () => notFound(),
    () => handleWebsiteIcon(env, 'example.com', 'not-found')
  );
  assert.equal(missing.result.status, 404);
  assert.equal(
    missing.result.headers.get('Cache-Control'),
    `public, max-age=${LIMITS.cache.iconFallbackTtlSeconds}`
  );

  const rejected = await withStubbedFetch(
    () => notFound(),
    () => handleWebsiteIcon(env, 'not a host')
  );
  assert.deepEqual(rejected.urls, []);
  assert.equal(
    rejected.result.headers.get('Cache-Control'),
    `public, max-age=${LIMITS.cache.iconFallbackTtlSeconds}`
  );
});

test('an upstream error status is not pinned at the edge for a week', async () => {
  const seen: Record<string, unknown>[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: unknown, init: any) => {
    seen.push(init?.cf);
    return notFound();
  }) as typeof fetch;
  try {
    await handleWebsiteIcon(env, 'example.com');
  } finally {
    globalThis.fetch = originalFetch;
  }

  // Every direct path, then both third parties.
  assert.equal(seen.length, DIRECT_URLS.length + 2);
  for (const cf of seen) {
    const byStatus = (cf as any)?.cacheTtlByStatus;
    assert.equal(byStatus['200-299'], LIMITS.cache.iconTtlSeconds);
    assert.equal(byStatus['400-499'], LIMITS.cache.iconFallbackTtlSeconds);
    assert.equal(byStatus['500-599'], 0);
  }
});

test('DISABLE_THIRD_PARTY_ICONS=1 keeps the lookup between this server and the site', async () => {
  const missed = await withStubbedFetch(
    () => notFound(),
    () => handleWebsiteIcon(noThirdPartyEnv, 'example.com')
  );
  assert.deepEqual(missed.urls, DIRECT_URLS);

  const found = await withStubbedFetch(
    (url) => (url === DIRECT_URLS[0] ? pngResponse() : notFound()),
    () => handleWebsiteIcon(noThirdPartyEnv, 'example.com')
  );
  assert.deepEqual(found.urls, [DIRECT_URLS[0]]);
  assert.equal(found.result.status, 200);
  assert.equal(found.result.headers.get('Content-Type'), 'image/png');
});

test("icons.bitwarden.net's generic globe is still not mistaken for an icon", async () => {
  const globe = new Uint8Array(500);
  const { result, urls } = await withStubbedFetch(
    (url) =>
      url === BITWARDEN_URL
        ? new Response(globe, { status: 200, headers: { 'Content-Type': 'image/png' } })
        : notFound(),
    () => handleWebsiteIcon(env, 'example.com')
  );

  // 500 zero bytes is the right length but the wrong hash, so it is kept;
  // the pairing of the two is what the reject rule is.
  assert.deepEqual(urls, [...DIRECT_URLS, FAVICON_IM_URL, BITWARDEN_URL]);
  assert.equal(result.headers.get('Content-Type'), 'image/png');
});
