---
name: auth-interface
description: AntelopeJS interface for token-based authentication - signing and verifying auth tokens (SignRaw, ValidateRaw, SignServerResponse) and injecting the verified payload into interface-api controllers via the @Authentication decorator or custom decorators from CreateAuthDecorator. Use when code imports "@antelopejs/interface-auth", when securing controller routes, generating or validating auth/JWT tokens, injecting authenticated user data into handler parameters, or when implementing an auth provider for internal.Verify/internal.Sign.
category: antelopejs-interface
tags: [antelopejs, auth, jwt, tokens, decorators]
---

# @antelopejs/interface-auth

Token authentication for AntelopeJS modules. Two layers:

- **Proxy crossings** (need a provider module loaded, e.g. a JWT module): `internal.Verify` and `internal.Sign`, wrapped by `SignRaw`, `ValidateRaw`, and `SignServerResponse`. Always async.
- **Consumer-side helpers** (no crossing by themselves): `Authentication` and `CreateAuthDecorator`, which build parameter providers on top of `@antelopejs/interface-api`.

## Imports

All symbols come from the package root (the exports map exposes no other code subpaths):

```ts
import {
  Authentication, CreateAuthDecorator,
  SignRaw, ValidateRaw, SignServerResponse,
  internal, // provider side only
  type AuthSource, type AuthVerifier, type AuthValidator,
  type SignOptions, type VerifyOptions, type CookieOptions,
} from "@antelopejs/interface-auth";
```

`@antelopejs/interface-api` and `@antelopejs/interface-core` are peerDependencies — the consuming module must have them installed.

## Consuming

```ts
import { Controller, Get, Post } from "@antelopejs/interface-api";
import { Authentication, SignRaw } from "@antelopejs/interface-auth";

interface UserSession { id: string; role: string; }

class UserController extends Controller("/users") {
  @Post("login")
  async login() {
    // Sign a payload into a token (proxy call to the auth provider)
    return SignRaw({ id: "42", role: "admin" }, { expiresIn: "1h" });
  }

  @Get("profile")
  async getProfile(@Authentication() user: UserSession) {
    // Token was read from the request, verified, and injected
    return { id: user.id, role: user.role };
  }
}
```

Custom pipelines use `CreateAuthDecorator({ source?, authenticator?, authenticatorOptions?, validator? })`; the callbacks run as `source(req, res)` → `authenticator(data, authenticatorOptions)` → `validator(data)` → injected parameter.

## Providing

An auth backend module implements the two proxy points:

```ts
import { ImplementInterface } from "@antelopejs/interface-core";
import { internal } from "@antelopejs/interface-auth";

ImplementInterface(internal, {
  Verify: (token, options) => decodeAndVerify(token, options), // return payload, throw on invalid
  Sign: (data, options) => signToken(data, options),           // return token string
});
```

Declare `"antelopeJs": { "implements": ["@antelopejs/interface-auth"] }` in the provider's package.json.

## Gotchas

- `SignRaw` / `ValidateRaw` / `SignServerResponse` are interface proxy calls: they return Promises and only resolve once a provider module is attached. Calls made earlier are queued, not failed — always `await`.
- Default token source (`internal.defaultSource`): the `x-antelopejs-auth` request header, falling back to the `ANTELOPEJS_AUTH` cookie. `SignServerResponse` sets that same cookie via `Set-Cookie`.
- `@Authentication(validator?)` accepts an optional validator at the use site; it overrides any validator configured in `CreateAuthDecorator`.
- Decorators from `CreateAuthDecorator` (including `Authentication`) apply to parameters, properties, and whole classes (class-level registers a provider for the controller) — NOT to methods; decorating a method silently registers nothing and can break other parameter decorators on that handler.
- `expiresIn` / `notBefore` (SignOptions) and `maxAge` (VerifyOptions) accept a number of seconds or a timespan string such as `"1h"`.
- Rejection is exception-based: a failed verification or validator throws, it does not return `undefined`.

## Deeper reference

See this package's `docs/` chapters — Introduction, Authentication Basics, Token Handling, Parameter Decoration — and the shipped `dist/index.d.ts` for full TSDoc signatures. Do not duplicate them here.
