# interface-auth

The AntelopeJS interface for token authentication, published as `@antelopejs/interface-auth`. The whole contract lives in `src/index.ts`; implementations such as `@antelopejs/auth-jwt` live in their own repositories.

## Versioning

`@antelopejs/interface-api` and `@antelopejs/interface-core` are peer dependencies with a `>=minimum <next minor` range. The devDependency on each pins the same range. When you raise a minimum, raise the peer range, the devDependency, and the compatibility table in `README.md` together. The `dependency:ranges` step of `pnpm run checks` caps every `@antelopejs/*` range below the next minor and gives each 1.x range `~`.

## Tests

- `pnpm test` builds `dist`, then runs `ajs module test .`. `src/antelope.test.ts` (`antelopeJs.test` in `package.json`) describes the test project: it loads `@antelopejs/auth-jwt` (a devDependency, as a local module), installs `@antelopejs/api` from npm at a pinned version, because `auth-jwt` declares `@antelopejs/interface-api`, and runs the compiled suites in `dist/tests`. The suites are written in `src/tests`. `antelope-lock/` records the lockfile each npm module installed with, and `ajs module test` installs from it, so every run tests the same dependencies; commit it when it changes, and refresh it by deleting the module's record and `.antelope/cache`, then running `pnpm test`. `pnpm-workspace.yaml` overrides the `@antelopejs/interface-auth` dependency of `@antelopejs/auth-jwt` with a link to this package, and the suites import the code under test by relative path, so they exercise the local build: without the override they would test the published copy the implementer installs. Do not import `@antelopejs/interface-auth` by name in a suite.
- The test project serves the API on `127.0.0.1:5010`, so that port must be free.
- `ajs module test` installs the modules with `corepack pnpm@<packageManager>` when corepack is on `PATH`, and with the `pnpm` on `PATH` otherwise. Node 25 and later do not bundle corepack, so there install pnpm 10.6.5 another way.
- `pnpm run checks` does not run the documentation check. CI runs it through the `docs-files` inputs in `.github/workflows/ci.yml`. To run it locally, clone `AntelopeJS/tooling-configs` at `v0.0.9` (the ref ci-node pins), run `npm ci --prefix actions/docs --omit=dev`, then run `node <clone>/actions/docs/check.mjs --files "$(printf 'README.md\ndocs')" --typescript-project docs/tsconfig.json` from this repository.

## Shipped files

- `docs/` and `skills/` ship in the npm package. `docs/` holds the guides the package `homepage` (interfaces.antelopejs.com/docs/auth) points to. `skills/` reaches users through `antelopeJs.skills`; when the contract changes, update `skills/auth-interface/SKILL.md`.

<!-- antelopejs-guardrails:start -->
<!-- Managed by @antelopejs/tooling-configs. `antelopejs-sync` rewrites everything between these markers; write repository-specific guidance outside them. -->

## Guardrails

CI runs `pnpm run checks` in full on every pull request and reports what failed. The commit hook formats and lints the staged files. Locally, run only the fast check for what you touched:

- `pnpm run typecheck` after you change types or signatures.
- `pnpm exec oxlint <files>` and `pnpm exec oxfmt <files>` on the files you changed.
- One test file, not the suite. In a module that tests with `ajs module test`: `pnpm run build`, then `pnpm exec ajs module test . -f dist/<path>.test.js`.

### Comments

Say it in code: a constraint in a type, a lint rule or a test, a public item's contract in TSDoc. Other comments are lint directives naming their rules, `@ts-expect-error <reason>`, `SAFETY: <reason>` above a type assertion, and license or tool directives. A reason states what the code does now.

### Tests

Each test names the wrong implementation it fails on, or is deleted. Drive behaviour through the public interface. An invariant over many files is a lint rule.

### Review

No tool checks these:

- A type guard checks the nested elements and values it claims.
- A no-upward import rule rejects same-tier peers; probe it with an import.
- A finding only an evasion or a patched internal can trigger goes under Attention and never blocks.

### Suppressions

`guardrails.suppressions.json` caps lint directives, `@ts-expect-error`, `SAFETY:` comments and rules a lint config turns off. Over a cap, fix the code or remove another suppression of that kind; only the operator raises a number. After removing suppressions, run `pnpm run suppressions:update` and commit the file.

<!-- antelopejs-guardrails:end -->
