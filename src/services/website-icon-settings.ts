import type { Env } from '../types';
import { StorageService } from './storage';

/**
 * Runtime settings for /icons, stored as one JSON blob in the config table.
 *
 * Only the third-party fallbacks are configurable. Asking the site itself for
 * its own favicon needs nobody's permission - it is one request to a host the
 * vault entry is already for - so there is nothing to switch there.
 */
export const WEBSITE_ICON_SETTINGS_KEY = 'icons.settings.v1';

export interface WebsiteIconSettings {
  thirdPartySourcesEnabled: boolean;
}

/**
 * What a server with no row and no variable does: exactly what it did before
 * either control existed, so upgrading changes no behaviour.
 */
const DEFAULT_WEBSITE_ICON_SETTINGS: WebsiteIconSettings = {
  thirdPartySourcesEnabled: true,
};

/**
 * How long one isolate may answer icon requests from a value it already read.
 *
 * handleWebsiteIcon runs per icon and made no D1 query at all before this
 * setting existed; a getConfigValue on every lookup would put a row read back
 * on that path for a vault's worth of domains at once. So the value is read at
 * most once per isolate per window, and a change made in the admin UI is
 * visible everywhere within it. The isolate that served the PUT sees it at
 * once - saveWebsiteIconSettings primes this cache - and so does any isolate
 * that had never read the value.
 */
export const WEBSITE_ICON_SETTINGS_CACHE_TTL_MS = 60_000;

let cachedSettings: WebsiteIconSettings | null = null;
let cachedUntil = 0;

function normalizeBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value === 'boolean') return value;
  if (value === 1 || value === '1' || value === 'true') return true;
  if (value === 0 || value === '0' || value === 'false') return false;
  return fallback;
}

export function normalizeWebsiteIconSettings(value: unknown): WebsiteIconSettings {
  const input = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  return {
    thirdPartySourcesEnabled: normalizeBoolean(
      input.thirdPartySourcesEnabled,
      DEFAULT_WEBSITE_ICON_SETTINGS.thirdPartySourcesEnabled
    ),
  };
}

/** An uncached read, for the admin endpoint that has to show the stored truth. */
export async function getWebsiteIconSettings(storage: StorageService): Promise<WebsiteIconSettings> {
  const raw = await storage.getConfigValue(WEBSITE_ICON_SETTINGS_KEY);
  if (!raw) return { ...DEFAULT_WEBSITE_ICON_SETTINGS };
  try {
    return normalizeWebsiteIconSettings(JSON.parse(raw));
  } catch {
    return { ...DEFAULT_WEBSITE_ICON_SETTINGS };
  }
}

export async function saveWebsiteIconSettings(
  storage: StorageService,
  settings: WebsiteIconSettings
): Promise<WebsiteIconSettings> {
  const normalized = normalizeWebsiteIconSettings(settings);
  await storage.setConfigValue(WEBSITE_ICON_SETTINGS_KEY, JSON.stringify(normalized));
  primeWebsiteIconSettingsCache(normalized);
  return normalized;
}

function primeWebsiteIconSettingsCache(settings: WebsiteIconSettings, now = Date.now()): void {
  cachedSettings = { ...settings };
  cachedUntil = now + WEBSITE_ICON_SETTINGS_CACHE_TTL_MS;
}

/** Drops the isolate's cached copy. Exists for tests. */
export function resetWebsiteIconSettingsCache(): void {
  cachedSettings = null;
  cachedUntil = 0;
}

async function readCachedWebsiteIconSettings(
  storage: StorageService,
  now: number
): Promise<WebsiteIconSettings> {
  if (cachedSettings && now < cachedUntil) return cachedSettings;
  try {
    const raw = await storage.getConfigValue(WEBSITE_ICON_SETTINGS_KEY);
    const settings = raw
      ? normalizeWebsiteIconSettings(JSON.parse(raw))
      : { ...DEFAULT_WEBSITE_ICON_SETTINGS };
    primeWebsiteIconSettingsCache(settings, now);
    return settings;
  } catch {
    // A database that is down or a row that is corrupt must not become one
    // failed query per icon, and must not quietly re-enable the third parties
    // on a server whose admin had turned them off: the last value this isolate
    // read wins, and only a process that never read one falls back to the
    // default.
    const fallback = cachedSettings || { ...DEFAULT_WEBSITE_ICON_SETTINGS };
    primeWebsiteIconSettingsCache(fallback, now);
    return fallback;
  }
}

/**
 * Whether DISABLE_THIRD_PARTY_ICONS=1 is set in the Worker's own configuration.
 */
export function isThirdPartyIconsDisabledByEnv(env: Env): boolean {
  return String(env.DISABLE_THIRD_PARTY_ICONS || '').trim() === '1';
}

export interface WebsiteIconSettingsView extends WebsiteIconSettings {
  disabledByEnv: boolean;
  effectiveThirdPartySourcesEnabled: boolean;
}

/**
 * The stored setting together with what is actually in force.
 *
 * Both are reported because they can disagree, and an admin looking at a
 * "third parties allowed" toggle deserves to be told when a Worker variable
 * they cannot see from the vault UI is overriding it. Turning the toggle back
 * on while DISABLE_THIRD_PARTY_ICONS=1 stores the value and changes nothing,
 * which is only honest if the response says so.
 */
export function describeWebsiteIconSettings(env: Env, settings: WebsiteIconSettings): WebsiteIconSettingsView {
  const disabledByEnv = isThirdPartyIconsDisabledByEnv(env);
  return {
    thirdPartySourcesEnabled: settings.thirdPartySourcesEnabled,
    disabledByEnv,
    effectiveThirdPartySourcesEnabled: disabledByEnv ? false : settings.thirdPartySourcesEnabled,
  };
}

/**
 * Whether favicon.im and icons.bitwarden.net may be asked about a domain.
 *
 * Two controls, and the environment variable is the harder of the two: setting
 * DISABLE_THIRD_PARTY_ICONS=1 takes an operator with access to the Worker's
 * configuration, and a row in a database this server also hands to its own
 * admin UI should not be able to undo it. The precedence is therefore
 *
 *   env var says disabled  -> disabled, whatever is stored
 *   otherwise              -> the stored setting decides
 *   neither present        -> allowed, which is what the server did before
 *
 * `now` is injectable so the staleness window above can be tested without
 * waiting a minute.
 */
export async function areThirdPartyIconSourcesAllowed(env: Env, now: number = Date.now()): Promise<boolean> {
  if (isThirdPartyIconsDisabledByEnv(env)) return false;
  // No database bound (tests, and the KV-only paths that never reach here):
  // there is no row to read, so the default stands.
  if (!env.DB) return DEFAULT_WEBSITE_ICON_SETTINGS.thirdPartySourcesEnabled;
  const settings = await readCachedWebsiteIconSettings(new StorageService(env.DB), now);
  return settings.thirdPartySourcesEnabled;
}
