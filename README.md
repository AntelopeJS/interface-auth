# @antelopejs/interface-auth

<div align="center">
<a href="https://www.npmjs.com/package/@antelopejs/interface-auth"><img alt="npm" src="https://img.shields.io/npm/v/@antelopejs/interface-auth?style=for-the-badge&labelColor=000000&color=000000"></a>
<a href="./LICENSE"><img alt="License" src="https://img.shields.io/npm/l/@antelopejs/interface-auth?style=for-the-badge&labelColor=000000&color=000000"></a>
<a href="https://discord.gg/sjK28QHrA7"><img alt="Discord" src="https://img.shields.io/badge/Discord-18181B?logo=discord&style=for-the-badge&color=000000"></a>
<a href="https://interfaces.antelopejs.com/docs/auth"><img alt="Docs" src="https://img.shields.io/badge/Docs-18181B?style=for-the-badge&color=000000"></a>
</div>

The AntelopeJS contract for token authentication: sign and verify tokens, and inject the verified payload into API handlers with a decorator.

## What it offers

- `SignRaw` and `ValidateRaw` sign a payload into a token and verify a token back into its payload.
- `SignServerResponse` signs a payload and attaches the token to a response as a cookie.
- `@Authentication()` reads the token from the `Authorization` header or the `ANTELOPEJS_AUTH` cookie, verifies it and injects the payload into a handler parameter.
- `CreateAuthDecorator` builds your own decorator with a custom source, verifier and validator.

## Implementations

| Module                                                           | Notes           |
| ---------------------------------------------------------------- | --------------- |
| [`@antelopejs/auth-jwt`](https://github.com/AntelopeJS/auth-jwt) | JSON Web Tokens |

## Install

Add the interface to the module that protects routes:

```bash
pnpm add @antelopejs/interface-auth
```

Then add an implementation to the project, with an implementation of the API interface:

```bash
ajs project modules add @antelopejs/auth-jwt @antelopejs/api
```

## Quick start

```ts
import { Controller, Get, Post } from "@antelopejs/interface-api";
import { Authentication, SignRaw } from "@antelopejs/interface-auth";

interface Session {
  id: string;
}

export class SessionController extends Controller("/session") {
  @Post("login")
  async login() {
    return SignRaw({ id: "user-7" }, { expiresIn: "1h" });
  }

  @Get("me")
  async me(@Authentication() session: Session) {
    return { id: session.id };
  }
}
```

A request to `GET /session/me` without a valid token fails before the handler runs.

## Documentation

- [Introduction](https://interfaces.antelopejs.com/docs/auth/introduction)
- [Authentication](https://interfaces.antelopejs.com/docs/auth/authentication)
- [Token handling](https://interfaces.antelopejs.com/docs/auth/token-handling)
- [Parameter decoration](https://interfaces.antelopejs.com/docs/auth/parameter-decoration)

## Compatibility

| Package                             | Range             |
| ----------------------------------- | ----------------- |
| `@antelopejs/interface-api` (peer)  | `>=0.0.13 <1.0.0` |
| `@antelopejs/interface-core` (peer) | `>=0.1.1 <1.0.0`  |
| `@antelopejs/core`                  | `1.x`             |

## Contributing

Read [CONTRIBUTING.md](./CONTRIBUTING.md) before you open a pull request. The local checks are:

```bash
pnpm install
pnpm lint
pnpm test
```

## License

[Apache-2.0](./LICENSE)
