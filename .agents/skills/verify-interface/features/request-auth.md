---
covers:
  - src/index.ts
docs:
  - docs/1.introduction.md
  - docs/2.authentication.md
  - docs/4.parameter-decoration.md
journeys:
  - default-source
  - check-authentication
  - auth-decorators
  - request-types
---

# Request authentication

A controller decorates a handler parameter, a property or the class with `@Authentication()` (or a decorator from `CreateAuthDecorator`) and receives the verified claims. The request goes through `source`, then `authenticator`, then an optional `validator`; any throw stops the handler.

## Sub-features

- `default-source`: the default source reads `x-antelopejs-auth`, then the `ANTELOPEJS_AUTH` cookie only when the header is absent; a present but empty header still wins, an array header yields its first value, a cookie is found among others and a lookalike name is not, `Authorization` is not read, and nothing found yields `undefined`.
- `check-authentication`: the pipeline runs `source(req, res)`, `authenticator(token, options)`, `validator(claims)` in that order; without a validator the claims pass unchanged; the validator's return value is injected as is, even `false`; a thrown validator or a rejected authenticator reaches the caller and later stages do not run; the default authenticator is `ValidateRaw`.
- `auth-decorators`: decorators applied for real to a Controller of `@antelopejs/interface-api` register a parameter provider on a parameter, a property and a class, and the provider answers with what the pipeline returns for a request: the default authenticator calls the provider with `{}` options, `authenticatorOptions` reach it, a decorator-level validator replaces the configured one, a custom source and authenticator bypass `ValidateRaw`, and a missing token reaches the provider.
- `request-types`: a probe compiled in strict mode against the packed declarations pins `AuthSource`, `AuthVerifier`, `AuthValidator` and the parameters of `CreateAuthDecorator` and `Authentication`, with the inferred types of the claims, in both directions.

## How to get to it (user POV)

- `getProfile(@Authentication() user: { name: string })` on an API controller, with the client sending the token in `x-antelopejs-auth` or the `ANTELOPEJS_AUTH` cookie.

## Driving it with antelopejs-verify

```bash
pnpm exec antelopejs-verify journey "$RUN" request-auth
```

## Gotchas

- No HTTP server runs: the decorators are applied to a real `Controller` and its parameter provider is called with a request context, which is what the API module does for each request. How the API module turns a thrown error into a status code is not part of this interface.
