<a href="https://github.com/AntelopeJS/antelopejs"><img data-illustration src="./.github/readme/strip.svg" width="100%" alt="INTERFACE · AUTH: part of AntelopeJS, hexagonal architecture beyond your own code. A glowing button reads Star AntelopeJS."></a>

<div align="center">

# `@antelopejs/interface-auth`

<a href="https://www.npmjs.com/package/@antelopejs/interface-auth"><img data-illustration alt="npm" src="https://img.shields.io/npm/v/@antelopejs/interface-auth?style=for-the-badge&labelColor=000000&color=000000"></a> <a href="./LICENSE"><img data-illustration alt="License" src="https://img.shields.io/npm/l/@antelopejs/interface-auth?style=for-the-badge&labelColor=000000&color=000000"></a> <a href="https://discord.gg/g4pFt6eXqu"><img data-illustration alt="Discord" src="https://img.shields.io/badge/Discord-18181B?logo=discord&style=for-the-badge&color=000000"></a> <a href="https://interfaces.antelopejs.com/docs/auth"><img data-illustration alt="Docs" src="https://img.shields.io/badge/Docs-18181B?style=for-the-badge&color=000000"></a> <a href="https://github.com/AntelopeJS/antelopejs"><img data-illustration alt="Star AntelopeJS" src="https://img.shields.io/github/stars/AntelopeJS/antelopejs?label=Star%20AntelopeJS&style=for-the-badge&labelColor=000000&color=000000&logo=github"></a>

**The AntelopeJS contract for token authentication. Sign and verify tokens and inject the verified payload into API handlers.**

[Documentation](https://interfaces.antelopejs.com/docs/auth) · [Implementations](#implementations) · [All interfaces and providers](https://github.com/AntelopeJS/antelopejs#ecosystem)

</div>

The AntelopeJS contract for token authentication: sign and verify tokens, and inject the verified payload into API handlers with a decorator.

## What it offers

- `SignRaw` and `ValidateRaw` sign a payload into a token and verify a token back into its payload.
- `SignServerResponse` signs a payload and attaches the token to a response as a cookie.
- `@Authentication()` reads the token from the `x-antelopejs-auth` header, or from the `ANTELOPEJS_AUTH` cookie when the header is absent. It verifies the token and injects the payload into a handler parameter.
- `CreateAuthDecorator` builds your own decorator with a custom source, verifier, and validator.

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

A request to `GET /session/me` without a valid token fails before the handler runs. Send the token unchanged in `x-antelopejs-auth`, without a `Bearer ` prefix. The `login` method only shows signing. In a real application, check the credentials before you issue a token.

The `Session` annotation describes the payload the application expects. It does not check it, so `session.id` is whatever the verified token carries. Add a [shape-checking verifier](./docs/2.authentication.md#create-a-custom-verifier) before you rely on claims from tokens whose format nothing enforces.

## Documentation

- [Introduction](./docs/1.introduction.md)
- [Authentication](./docs/2.authentication.md)
- [Token handling](./docs/3.token-handling.md)
- [Parameter decoration](./docs/4.parameter-decoration.md)

## Compatibility

The module declares these peer dependencies:

<!-- antelopejs-docs-compat:start -->

| Package                      | Supported         | Tested with |
| ---------------------------- | ----------------- | ----------- |
| `@antelopejs/interface-api`  | `>=0.0.15 <1.0.0` | `0.2.0`     |
| `@antelopejs/interface-core` | `>=0.2.4 <1.0.0`  | `0.4.0`     |

<!-- antelopejs-docs-compat:end -->

## Contributing

Read [CONTRIBUTING.md](./CONTRIBUTING.md) before you open a pull request. The local checks are:

```bash
pnpm install
pnpm lint
pnpm test
```

## Part of AntelopeJS

[AntelopeJS](https://github.com/AntelopeJS/antelopejs) is the TypeScript framework where modules depend on contracts and the application chooses the provider. [AntelopeJS DMS](https://github.com/AntelopeJS/dms) is built on it.

<!-- antelopejs-framework-modules:start -->

| Area         | Contracts                                                                                                                                                                                                                                                                                                                                                                                                                  | Providers                                                                                                                                                                                                                                           |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| API          | [`interface-api`](https://github.com/AntelopeJS/interface-api) · [`interface-api-util`](https://github.com/AntelopeJS/interface-api-util) · [`interface-data-api`](https://github.com/AntelopeJS/interface-data-api)                                                                                                                                                                                                       | [`api`](https://github.com/AntelopeJS/api)                                                                                                                                                                                                          |
| Auth         | **`interface-auth`**                                                                                                                                                                                                                                                                                                                                                                                                       | [`auth-jwt`](https://github.com/AntelopeJS/auth-jwt)                                                                                                                                                                                                |
| Database     | [`interface-database`](https://github.com/AntelopeJS/interface-database) · [`interface-database-decorators`](https://github.com/AntelopeJS/interface-database-decorators) · [`interface-database-catalog`](https://github.com/AntelopeJS/interface-database-catalog) · [`interface-mongodb`](https://github.com/AntelopeJS/interface-mongodb) · [`interface-rethinkdb`](https://github.com/AntelopeJS/interface-rethinkdb) | [`postgres`](https://github.com/AntelopeJS/postgres) · [`mongodb`](https://github.com/AntelopeJS/mongodb) · [`rethinkdb`](https://github.com/AntelopeJS/rethinkdb)                                                                                  |
| Redis        | [`interface-redis`](https://github.com/AntelopeJS/interface-redis) · [`interface-redis-scheduler`](https://github.com/AntelopeJS/interface-redis-scheduler)                                                                                                                                                                                                                                                                | [`redis`](https://github.com/AntelopeJS/redis)                                                                                                                                                                                                      |
| Email        | [`interface-email`](https://github.com/AntelopeJS/interface-email)                                                                                                                                                                                                                                                                                                                                                         | [`nodemailer`](https://github.com/AntelopeJS/nodemailer) · [`brevo`](https://github.com/AntelopeJS/brevo)                                                                                                                                           |
| File storage | [`interface-file-storage`](https://github.com/AntelopeJS/interface-file-storage)                                                                                                                                                                                                                                                                                                                                           | [`file-storage-local`](https://github.com/AntelopeJS/file-storage-local) · [`file-storage-s3`](https://github.com/AntelopeJS/file-storage-s3)                                                                                                       |
| Payments     | [`interface-payment`](https://github.com/AntelopeJS/interface-payment) · [`interface-subscriptions`](https://github.com/AntelopeJS/interface-subscriptions) · [`interface-stripe`](https://github.com/AntelopeJS/interface-stripe)                                                                                                                                                                                         | [`stripe`](https://github.com/AntelopeJS/stripe) · [`mollie`](https://github.com/AntelopeJS/mollie) · [`checkout-com`](https://github.com/AntelopeJS/checkout-com) · [`payment-subscriptions`](https://github.com/AntelopeJS/payment-subscriptions) |

<!-- antelopejs-framework-modules:end -->

## License

[Apache-2.0](./LICENSE)
