# ADR-013: TypeScript-checked UI modules without a framework or build step

Status: accepted, 2026-10-08. Revisit when the criteria below are met.

## Context

The browser endpoint (`apps/unit-client`, 1 396-line `app.mjs`) and admin console are dependency-free
ES modules served as an offline-capable shell (`sw.js`). Operators saw raw authority codes such as
`USER_REVOKED`. Only nine files were type-checked. The directive asks for a TypeScript-first UI with
three permission-separated experiences and an evaluation of React.

Constraints that any UI choice must keep:

- Zero npm runtime dependencies (`scripts/check.mjs` enforces it) and an offline/air-gap target.
- ADR-007: the service-worker shell is an immutable generation; `crypto.mjs` imports only
  `canonical.mjs`; every shell module must be listed in `sw.js` and the generation bumped.
- Private keys and plaintext never leave the endpoint; the authority is the only enforcement point.

## Decision

1. **No React (or other framework) now.** It would add runtime dependencies, a bundler and its supply
   chain to an offline security client, and change the module-graph invariant, with no measured need.
2. **TypeScript-strict checking of UI logic** with JSDoc types under `tsconfig.json` (`strict`,
   `checkJs`): no build step, no emitted code that differs from the reviewed source, no new
   dependencies. New UI logic lives in small, pure, typed modules that are unit-tested in Node.
3. **First slice (implemented):**
   - `apps/unit-client/decisions.mjs`: content-free explanations for every authority decision code
     (title, explanation, who can act, guidance, severity). Unknown codes fail safe as "held". A
     test scans the authority sources and fails on any unexplained or stale code.
   - `apps/unit-client/capabilities.mjs`: deny-by-default capability model mirroring the authority's
     role checks; one experience per role (`unit-operator`, `administrator`,
     `security-evaluation`); a drift test pins it to `core.mjs`.
   - Both UIs use them; `sw.js` lists both modules and the shell generation is `v7`. The browser
     acceptance asserts the explanation is rendered for a real held object.

## Criteria to revisit (any one)

- The UI needs client-side state shared across more than three independently updating views, or
  component reuse that DOM helpers make error-prone (measured by defects, not taste).
- A desktop shell (Tauri) is adopted for hardware key custody; its webview could then host a
  framework without changing the browser endpoint.
- Accessibility or usability evaluation shows failures the current structure cannot fix cheaply.

## Remaining UI work (not done)

Decomposing `app.mjs` into typed modules; a dedicated security/evaluation view (evidence verification,
crypto inventory, recovery state, monitoring health); accessibility audit with assistive technology;
task-based usability evaluation with representative users. None of these is claimed.
