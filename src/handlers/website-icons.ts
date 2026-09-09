import { LIMITS } from '../config/limits';
import type { Env } from '../types';
import { isSafeWebsiteIconContentType } from '../utils/content-type';

// Per-attempt budgets. The origin gets a shorter one than the third parties:
// it is one request to a host the user already has an account with, and three
// paths are tried, so a slow origin must not be able to spend the whole
// budget on its own.
const ICON_DIRECT_TIMEOUT_MS = 1500;
const ICON_UPSTREAM_TIMEOUT_MS = 2500;
// Ceiling for the whole resolution, however many sources it walks. Without it
// the direct attempts would simply be added to the two upstream timeouts and a
// miss would cost more than it does today, not less.
const ICON_TOTAL_BUDGET_MS = 5000;
const ICON_MAX_BUFFER_BYTES = 256 * 1024;
// Redirect hops a direct-origin fetch will follow. Each one is re-validated
// by the same host rules as the first request; see resolveDirectIconRedirect.
const ICON_MAX_REDIRECTS = 3;
const ICON_REQUEST_HEADERS = { 'User-Agent': 'NodeWarden/1.0' };

const BITWARDEN_DEFAULT_GLOBE_ICON_BYTES = 500;
const BITWARDEN_DEFAULT_GLOBE_ICON_SHA256 = 'aaa64871332ad5b7d28fe8874efb19c2d9cc2f1e6de75d52b080b438225a0783';

// The paths a direct-origin fetch tries, in order. /favicon.ico is first
// because it is the one location a web server answers whether or not anybody
// configured it; the two PNG paths follow for sites that serve a modern icon
// and leave /favicon.ico as a 404.
//
// The list is short on purpose. Each entry is an outbound request, and the
// thorough way to find a site's declared icon - fetch the page, parse its
// <link rel="icon"> - means this server fetching somebody's HTML on behalf of
// a vault entry. Three fixed paths, or nothing.
const DIRECT_ICON_PATHS = ['favicon.ico', 'favicon.png', 'apple-touch-icon.png'] as const;

// Names that are reserved, unresolvable on the public internet, or resolve
// differently on a private network than they do here. A direct fetch to one
// of them is never a site icon; it is this Worker being pointed at something
// on the far side of a network boundary.
const NON_PUBLIC_ICON_HOST_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.intranet',
  '.lan',
  '.home',
  '.home.arpa',
  '.corp',
  '.private',
  '.test',
  '.example',
  '.invalid',
  '.onion',
] as const;

/**
 * Whether the icon endpoint answers at all. It always does: the direct-origin
 * source below needs no third party and is the private option, so there is
 * nothing here for a deployment to turn off. The third-party fallbacks have
 * their own switch - see areThirdPartyIconSourcesEnabled.
 */
export function isWebsiteIconProxyEnabled(env: Env): boolean {
  return true;
}

/**
 * Whether the endpoint may fall back to favicon.im and icons.bitwarden.net.
 * Set DISABLE_THIRD_PARTY_ICONS=1 to keep every icon lookup between this
 * server and the site the entry is for; sites that answer none of
 * DIRECT_ICON_PATHS then get the placeholder instead.
 */
export function areThirdPartyIconSourcesEnabled(env: Env): boolean {
  return String(env.DISABLE_THIRD_PARTY_ICONS || '').trim() !== '1';
}

function getDefaultWebsiteIconSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96" role="img" aria-label="Globe icon"><circle cx="48" cy="48" r="34" fill="none" stroke="#8ea9c7" stroke-width="6"/><path d="M14 48h68M48 14c10 10 16 21.5 16 34s-6 24-16 34c-10-10-16-21.5-16-34s6-24 16-34zm-24 10c8 5 17 8 24 8s16-3 24-8m-48 48c8-5 17-8 24-8s16 3 24 8" fill="none" stroke="#8ea9c7" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}

/**
 * The placeholder served when no source produced an icon.
 *
 * It is cached for minutes, not the week iconTtlSeconds buys a real icon, and
 * never immutable. A miss is usually a statement about one slow second, not
 * about the domain: with the long TTL a single timeout marked a site iconless
 * at the edge and in every client for seven days.
 */
export function handleNwFavicon(): Response {
  return new Response(getDefaultWebsiteIconSvg(), {
    status: 200,
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': `public, max-age=${LIMITS.cache.iconFallbackTtlSeconds}`,
    },
  });
}

export function handleMissingWebsiteIcon(): Response {
  return new Response(null, {
    status: 404,
    headers: {
      'Cache-Control': `public, max-age=${LIMITS.cache.iconFallbackTtlSeconds}`,
    },
  });
}

/**
 * The host from a /icons/{host}/icon.png path, or null if it is not one.
 *
 * The round-trip through URL is what does the work: a host only survives if
 * the parser hands back exactly the text that went in, so every alternate
 * spelling of an address normalizes to something else and is rejected here.
 * That covers 2130706433, 0x7f.1, 127.1 and [::ffff:127.0.0.1] - all of which
 * are 127.0.0.1 to a resolver - as well as ports, userinfo and percent-encoded
 * path separators. It does not cover an address already written in its
 * canonical form; isPublicIconHost below is what rejects those.
 */
export function normalizeIconHost(rawHost: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(String(rawHost || '').trim()).toLowerCase().replace(/\.+$/, '');
  } catch {
    return null;
  }
  if (!decoded || decoded.includes('/') || decoded.includes('\\')) return null;
  try {
    const parsed = new URL(`https://${decoded}`);
    return parsed.hostname === decoded ? decoded : null;
  } catch {
    return null;
  }
}

/**
 * Whether a normalized host may be fetched directly by this Worker.
 *
 * This is the SSRF gate, and it is deliberately stricter than "not a private
 * address". Proxying to two fixed services could not be aimed anywhere; a
 * direct fetch can, so the rule is that only a public domain name is dialled:
 *
 * - No IP literal, of either family, public or private. A vault entry's icon
 *   is fetched by name; an entry written as an address has no favicon worth
 *   the risk of getting the RFC1918 / loopback / link-local / unique-local
 *   boundaries wrong. Rejecting the whole shape removes that class of bug,
 *   and 169.254.169.254 with it.
 * - No single-label host. localhost, router and nas are the names a resolver
 *   completes against a search domain, and a dot is what a real site has.
 * - No reserved or private-use suffix (NON_PUBLIC_ICON_HOST_SUFFIXES).
 *
 * What it cannot see is DNS: a public name whose A record points into private
 * space still passes, because a Worker resolves nothing itself and cannot pin
 * the address it connects to. What bounds that residue is everything after
 * this check - the response is only ever read as an image, capped at
 * ICON_MAX_BUFFER_BYTES, and no upstream status, header or error text reaches
 * the caller. A miss and a refusal are the same placeholder.
 */
export function isPublicIconHost(host: string | null): boolean {
  if (!host) return false;
  // IPv6 literals arrive bracketed and always contain a colon; a bare colon
  // cannot reach here from normalizeIconHost either way.
  if (host.includes(':') || host.startsWith('[')) return false;
  const labels = host.split('.');
  if (labels.length < 2) return false;
  if (labels.some((label) => label.length === 0)) return false;
  // A host whose last label is all digits is an IPv4 address as far as URL
  // parsing is concerned, so this rejects every dotted-quad that reached here.
  if (/^\d+$/.test(labels[labels.length - 1])) return false;
  return !NON_PUBLIC_ICON_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

type IconSource = {
  url: string;
  // Direct-origin sources talk to the site itself, so they follow redirects
  // by hand and re-validate every hop. The third parties are fixed hosts and
  // do not need it.
  direct?: boolean;
  timeoutMs: number;
  rejectImage?: {
    byteLength: number;
    sha256: string;
  };
};

/**
 * Every source for one host, in the order they are tried.
 *
 * Direct first: it is the only private option and, for a site that answers,
 * the fastest one. favicon.im and icons.bitwarden.net keep their existing
 * order behind it. That order is no longer about speed - direct-first settled
 * that - but about how few requests each third party sees: whichever is last
 * is asked only about the domains the one before it also missed, and
 * icons.bitwarden.net is the service a self-hosted server exists to avoid.
 * It is also the weaker signal of the two, answering a generic globe rather
 * than a 404 for a domain it does not know, which the hash below has to
 * undo.
 */
export function buildIconSources(env: Env, normalizedHost: string): IconSource[] {
  const sources: IconSource[] = [];

  // https only, never a downgrade to http: a plaintext request announces
  // which domain is being asked about to every hop in between, which is the
  // disclosure this whole change is about.
  if (isPublicIconHost(normalizedHost)) {
    for (const path of DIRECT_ICON_PATHS) {
      sources.push({
        url: `https://${normalizedHost}/${path}`,
        direct: true,
        timeoutMs: ICON_DIRECT_TIMEOUT_MS,
      });
    }
  }

  if (areThirdPartyIconSourcesEnabled(env)) {
    const encodedHost = encodeURIComponent(normalizedHost);
    sources.push({
      url: `https://favicon.im/zh/${encodedHost}?larger=true&throw-error-on-404=true`,
      timeoutMs: ICON_UPSTREAM_TIMEOUT_MS,
    });
    sources.push({
      url: `https://icons.bitwarden.net/${encodedHost}/icon.png`,
      timeoutMs: ICON_UPSTREAM_TIMEOUT_MS,
      rejectImage: {
        byteLength: BITWARDEN_DEFAULT_GLOBE_ICON_BYTES,
        sha256: BITWARDEN_DEFAULT_GLOBE_ICON_SHA256,
      },
    });
  }

  return sources;
}

function remainingMs(deadlineAt: number): number {
  return deadlineAt - Date.now();
}

async function fetchIconUrl(
  url: string,
  deadlineAt: number,
  redirect: 'follow' | 'manual'
): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Math.max(remainingMs(deadlineAt), 0));
  try {
    return await fetch(url, {
      headers: ICON_REQUEST_HEADERS,
      redirect,
      signal: controller.signal,
      cf: {
        cacheEverything: true,
        // Only a real icon earns the week. A 404 or a 5xx from any source is
        // the moment, not the domain, and pinning it at the edge for seven
        // days is how a site that gained a favicon kept showing a monogram.
        cacheTtlByStatus: {
          '200-299': LIMITS.cache.iconTtlSeconds,
          '300-399': 0,
          '400-499': LIMITS.cache.iconFallbackTtlSeconds,
          '500-599': 0,
        },
      },
    } as RequestInit & { cf: Record<string, unknown> });
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * The absolute URL a direct-origin redirect may be followed to, or null to
 * refuse it.
 *
 * A public host redirecting to a private one is the way an SSRF check that
 * only looks at the first URL gets walked past, and Workers' own docs warn
 * that redirect: 'follow' forwards headers across hosts. So the hop is
 * resolved here and put through the same rules as the original request:
 * https only, a public host name, and no port - a redirect to :8443 turns
 * this endpoint into a port prober against a host that is otherwise fine.
 */
export function resolveDirectIconRedirect(fromUrl: string, location: string | null): string | null {
  if (!location) return null;
  let target: URL;
  try {
    target = new URL(location, fromUrl);
  } catch {
    return null;
  }
  if (target.protocol !== 'https:') return null;
  if (target.port !== '') return null;
  if (target.username || target.password) return null;
  if (!isPublicIconHost(normalizeIconHost(target.hostname))) return null;
  return target.toString();
}

/**
 * One direct-origin path, following up to ICON_MAX_REDIRECTS validated hops.
 *
 * Returns null when a hop is refused or the chain runs long; throws whatever
 * fetch throws when the host does not answer, which the caller reads as "this
 * host is unreachable" and uses to stop trying the other paths on it.
 */
async function fetchDirectIcon(url: string, deadlineAt: number): Promise<Response | null> {
  let current = url;
  for (let hop = 0; hop <= ICON_MAX_REDIRECTS; hop += 1) {
    if (remainingMs(deadlineAt) <= 0) return null;
    const response = await fetchIconUrl(current, deadlineAt, 'manual');
    if (response.status < 300 || response.status > 399) return response;
    const next = resolveDirectIconRedirect(current, response.headers.get('Location'));
    if (!next) return null;
    current = next;
  }
  return null;
}

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function getPositiveContentLength(headers: Headers): number | null {
  const raw = headers.get('Content-Length');
  if (!raw) return null;
  const value = Number(raw);
  return Number.isFinite(value) && value > 0 ? value : null;
}

async function readIconBytes(
  response: Response,
  maxBytes: number,
  deadlineAt: number
): Promise<ArrayBuffer | null> {
  if (!response.body) return null;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    void reader.cancel().catch(() => undefined);
  }, Math.max(remainingMs(deadlineAt), 0));

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;

      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }

  if (timedOut || totalBytes === 0) return null;

  const output = new ArrayBuffer(totalBytes);
  const bytes = new Uint8Array(output);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function iconResponse(body: BodyInit | null, contentType: string | null): Response {
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': contentType || 'image/png',
      'Cache-Control': `public, max-age=${LIMITS.cache.iconTtlSeconds}, immutable`,
      'Content-Security-Policy': "default-src 'none'; img-src 'self' data:; sandbox",
    },
  });
}

export async function handleWebsiteIcon(
  env: Env,
  host: string,
  fallbackMode: 'default' | 'not-found' = 'default'
): Promise<Response> {
  const fallback = () => (fallbackMode === 'not-found' ? handleMissingWebsiteIcon() : handleNwFavicon());

  if (!isWebsiteIconProxyEnabled(env)) return fallback();

  const normalizedHost = normalizeIconHost(host);
  if (!normalizedHost) return fallback();

  const totalDeadlineAt = Date.now() + ICON_TOTAL_BUDGET_MS;
  let directHostUnreachable = false;

  for (const source of buildIconSources(env, normalizedHost)) {
    if (source.direct && directHostUnreachable) continue;

    const budgetMs = Math.min(source.timeoutMs, remainingMs(totalDeadlineAt));
    if (budgetMs <= 0) break;
    const deadlineAt = Date.now() + budgetMs;

    let response: Response | null;
    try {
      response = source.direct
        ? await fetchDirectIcon(source.url, deadlineAt)
        : await fetchIconUrl(source.url, deadlineAt, 'follow');
    } catch {
      // Nothing answered: a DNS failure, a refused connection, or the budget
      // running out. The remaining direct paths are on that same host and
      // would fail the same way, so the direct stage ends here instead of
      // paying the timeout twice more.
      if (source.direct) directHostUnreachable = true;
      continue;
    }

    if (!response || !response.ok) continue;

    const contentType = String(response.headers.get('Content-Type') || '').toLowerCase();
    // Also what stops a single-page app that serves index.html for
    // /favicon.ico from becoming this host's icon.
    if (!isSafeWebsiteIconContentType(contentType)) continue;

    const contentLength = getPositiveContentLength(response.headers);
    if (contentLength !== null && contentLength > ICON_MAX_BUFFER_BYTES) continue;

    const bytes = await readIconBytes(response, ICON_MAX_BUFFER_BYTES, deadlineAt);
    if (!bytes) continue;
    if (
      source.rejectImage &&
      bytes.byteLength === source.rejectImage.byteLength &&
      (await sha256Hex(bytes)) === source.rejectImage.sha256
    ) {
      continue;
    }

    return iconResponse(bytes, response.headers.get('Content-Type'));
  }

  return fallback();
}
