/**
 * The one deletion date that means "this Send does not expire", and the only
 * correct way to ask whether a date is it.
 *
 * This lives in `shared/` rather than beside the rest of the Send limits because
 * both halves of the product have to agree on it: the worker validates against
 * it in `handlers/sends-shared.ts`, and the webapp has to recognise it so the
 * Sends screen says "Never" instead of rendering the year 9999 at the user.
 * `src/config/limits.ts` still owns the *reasoning* for the value -- see the
 * comment above `LIMITS.send.neverDeletionDate` -- and imports the literal from
 * here, so there is exactly one spelling of it in the repository.
 */
export const SEND_NEVER_DELETION_DATE = '9999-12-31T23:59:59.999Z';

/**
 * The furthest a *finite* Send deletion date may be from now, in days.
 *
 * Here for the same reason as the sentinel above: the worker enforces it in
 * `validateDeletionDate` and the composer has to offer it, so a second spelling
 * in the webapp is a second thing to forget. The webapp cannot reach
 * `src/config/limits.ts` -- it resolves `@shared/*` and nothing else outside
 * `webapp/src` -- which is how the Sends form came to cap its input at 31 and
 * go on capping it there after the server's own ceiling moved.
 *
 * `LIMITS.send.maxDeletionDays` still owns the reasoning for the value; see the
 * comment beside it, including why "forever" is NOT this number made larger.
 */
export const SEND_MAX_DELETION_DAYS = 3653;

const NEVER_DELETION_MS = new Date(SEND_NEVER_DELETION_DATE).getTime();

/**
 * Whether `value` is the never-expires sentinel rather than a real deadline.
 *
 * The comparison is numeric, not textual, and deliberately so: `...999Z` and
 * `...999+00:00` are the same instant and a client may send either, so a
 * `=== SEND_NEVER_DELETION_DATE` string test would call one of them a real
 * deletion date in the year 9999 and the other never.
 *
 * Accepts a `Date`, an ISO string, or an epoch-milliseconds number, because the
 * worker holds this as a parsed `Date` during validation while the webapp holds
 * the raw string off the wire, and neither should have to convert first.
 */
export function isNeverSendDeletionDate(value: Date | string | number | null | undefined): boolean {
  if (value === null || value === undefined || value === '') return false;
  const ms = value instanceof Date ? value.getTime() : new Date(value).getTime();
  return ms === NEVER_DELETION_MS;
}
