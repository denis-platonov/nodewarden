// Test-only shim for the `cloudflare:workers` module specifier.
//
// The Send validators worth testing are pure, but they live in
// `src/handlers/sends-shared.ts`, which imports the notifications hub, which
// extends `DurableObject` from `cloudflare:workers`. That specifier only exists
// inside workerd, so plain `node --test` / `tsx --test` cannot even load the
// module graph -- it fails at resolution with ERR_UNSUPPORTED_ESM_URL_SCHEME
// before a single assertion runs.
//
// Rather than reshape live handler code to suit the test runner, resolve that one
// specifier to a stub that supplies just enough for the class declaration to be
// evaluated. Nothing under test touches either export: `DurableObject` is only
// extended, never constructed, and `waitUntil` is only called from request paths
// these tests do not enter. Preload with `tsx --test --import`.
import { registerHooks } from 'node:module';

const STUB_SOURCE = [
  'export class DurableObject {',
  '  constructor(ctx, env) { this.ctx = ctx; this.env = env; }',
  '}',
  'export function waitUntil() {}',
  'export default {};',
].join('\n');

const STUB_URL = 'data:text/javascript,' + encodeURIComponent(STUB_SOURCE);

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'cloudflare:workers') {
      return { url: STUB_URL, format: 'module', shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
});
