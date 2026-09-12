import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LIMITS } from '../src/config/limits';
import { SEND_NEVER_DELETION_DATE, isNeverSendDeletionDate } from '../shared/send-deletion';
import { isNeverDeletionDate, isSendAvailable, validateDeletionDate } from '../src/handlers/sends-shared';
import { SendAuthType, SendType, type Send } from '../src/types';

// The deletion-date ceiling moved from 31 days to ten years and grew a sentinel
// that means "never". Sends had no server-side tests at all when that landed, so
// these pin the three things the change is easy to break: the sentinel is a value
// of its own and not merely a date near the ceiling, the ceiling is a real bound
// on either side of it, and the refusal message states the current limit instead
// of the number that used to be hard-coded into the sentence.

const DAY_MS = 24 * 60 * 60 * 1000;

function daysFromNow(days: number, offsetMs = 0): Date {
  return new Date(Date.now() + days * DAY_MS + offsetMs);
}

async function refusalMessage(date: Date): Promise<string> {
  const response = validateDeletionDate(date);
  assert.ok(response, 'expected the deletion date to be refused');
  assert.equal(response.status, 400);
  return await response.text();
}

function sendWithDeletionDate(deletionDate: string): Send {
  return {
    id: 'send-1',
    userId: 'user-1',
    type: SendType.Text,
    name: 'name',
    notes: null,
    data: '{}',
    key: 'key',
    passwordHash: null,
    passwordSalt: null,
    passwordIterations: null,
    authType: SendAuthType.None,
    emails: null,
    maxAccessCount: null,
    accessCount: 0,
    disabled: false,
    hideEmail: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    expirationDate: null,
    deletionDate,
  };
}

test('the never sentinel validates', () => {
  assert.equal(validateDeletionDate(new Date(LIMITS.send.neverDeletionDate)), null);
  assert.equal(LIMITS.send.neverDeletionDate, SEND_NEVER_DELETION_DATE);
});

test('one millisecond before the sentinel is refused', async () => {
  // The sentinel is not "the far end of the allowed range"; it is its own value.
  // A date one tick below it is an ordinary finite date, centuries past the
  // ceiling, and must be refused -- otherwise "never" would have been implemented
  // as "very large", and every near-9999 typo would quietly become permanent.
  const justBefore = new Date(new Date(SEND_NEVER_DELETION_DATE).getTime() - 1);
  assert.equal(isNeverDeletionDate(justBefore), false);
  const message = await refusalMessage(justBefore);
  assert.match(message, /deletion date that far into the future/i);
});

test('a date at the ceiling passes and a date past it fails', async () => {
  // validateDeletionDate reads Date.now() itself, after we do, so its ceiling is
  // at or above the one computed here: a date exactly at ours cannot land above
  // its own. A minute of slack past the ceiling cannot be closed the same way.
  assert.equal(validateDeletionDate(daysFromNow(LIMITS.send.maxDeletionDays)), null);
  assert.equal(validateDeletionDate(daysFromNow(LIMITS.send.maxDeletionDays - 1)), null);
  assert.equal(validateDeletionDate(daysFromNow(1)), null);

  const message = await refusalMessage(daysFromNow(LIMITS.send.maxDeletionDays, 60_000));
  assert.match(message, /deletion date that far into the future/i);
});

test('the refusal states the current limit and never the retired 31', async () => {
  // The regression this guards: the sentence used to read "less than 31 days"
  // with the number spelled into the prose, so raising the limit left the server
  // telling users a bound it no longer enforced.
  const message = await refusalMessage(daysFromNow(LIMITS.send.maxDeletionDays + 1));
  assert.ok(
    message.includes(String(LIMITS.send.maxDeletionDays)),
    `refusal must name the limit ${LIMITS.send.maxDeletionDays}: ${message}`
  );
  assert.equal(message.includes('31'), false, `refusal must not spell a stale limit: ${message}`);
});

test('a Send dated with the sentinel is available', () => {
  // isSendAvailable has no arm for the sentinel on purpose -- it compares the
  // deadline to now like any other date. This asserts that the sentinel is far
  // enough out for that to be the right answer, which is the whole reason a date
  // was chosen over a nullable column.
  assert.equal(isSendAvailable(sendWithDeletionDate(SEND_NEVER_DELETION_DATE)), true);
  assert.equal(isSendAvailable(sendWithDeletionDate(new Date(Date.now() - 1000).toISOString())), false);
});

test('the sentinel is recognised however a client spells the instant', () => {
  // Numeric comparison, not string equality: these are all the same moment.
  assert.equal(isNeverDeletionDate(new Date('9999-12-31T23:59:59.999+00:00')), true);
  assert.equal(isNeverDeletionDate(new Date('9999-12-31T18:59:59.999-05:00')), true);
  assert.equal(isNeverDeletionDate(new Date('9999-12-31T23:59:59.999Z')), true);
  assert.equal(isNeverSendDeletionDate('9999-12-31T23:59:59.999+00:00'), true);
  assert.equal(isNeverSendDeletionDate('9999-12-31T18:59:59.999-05:00'), true);
  assert.equal(isNeverSendDeletionDate(new Date(SEND_NEVER_DELETION_DATE).getTime()), true);

  assert.equal(isNeverDeletionDate(new Date('9999-12-31T23:59:59.998Z')), false);
  assert.equal(isNeverSendDeletionDate(null), false);
  assert.equal(isNeverSendDeletionDate(undefined), false);
  assert.equal(isNeverSendDeletionDate(''), false);
  assert.equal(isNeverSendDeletionDate('not a date'), false);
});
