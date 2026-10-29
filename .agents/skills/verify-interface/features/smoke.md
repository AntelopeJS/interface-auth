---
covers:
docs:
  - docs/1.introduction.md
journeys:
  - core-functions
---

# Smoke

The fixed journeys every verdict runs, whatever the diff touches: pack the interface, load it in `ajs project dev` with a stub provider behind `internal.Sign` and `internal.Verify` and a consumer, and call every runtime function through core.

## Sub-features

- `core-functions`: the packed interface exports exactly `Authentication`, `CreateAuthDecorator`, `SignRaw`, `SignServerResponse`, `ValidateRaw` and the `internal` functions `CheckAuthentication`, `Sign`, `Verify`, `defaultAuthenticator` and `defaultSource`; each answers through core in `ajs project dev` with the value `verify.config.ts` expects, and `internal.Sign` and `internal.Verify` answer the stub provider (`Sign` returns `tok:<JSON of the data>`, `Verify` returns the token and options it received).

## How to get to it (user POV)

- A project with an auth module (such as auth-jwt) and a module that imports `@antelopejs/interface-auth`.

## Driving it with antelopejs-verify

```bash
pnpm exec antelopejs-verify journey "$RUN" smoke
```

## Gotchas

- The smoke feature covers no glob, so it never marks a file as mapped.
- The shared `every-function` and `minor-bump` journeys are not listed: the released pack (0.2.12) reads the declarations with `types: []` and stops on the `node:http` import of these declarations (fixed in tooling-configs#53, unreleased). `core-functions` stands in for `every-function`; nothing here compares the functions with the published version until `minor-bump` can run.
