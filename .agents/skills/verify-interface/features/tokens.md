---
covers:
  - src/index.ts
docs:
  - docs/1.introduction.md
  - docs/3.token-handling.md
journeys:
  - sign-and-verify
  - token-types
---

# Tokens

A module calls `SignRaw(data, options?)` to get a signed token string and `ValidateRaw(token?, options?)` to get the claims back. Both go through the provider module that implements `internal.Sign` and `internal.Verify`; this interface adds no check of its own.

## Sub-features

- `sign-and-verify`: against a recording stand-in provider attached to `internal.Sign` and `internal.Verify`: `SignRaw` hands the data and the sign options to the provider and resolves to its token; `ValidateRaw` hands the token and the verify options over and resolves to the claims, an object or a string as the provider answers; a missing token still reaches the provider; a provider rejection reaches the caller unchanged.
- `token-types`: a probe compiled in strict mode against the packed declarations pins the parameters and the answer of `SignRaw` and `ValidateRaw`, and the exact shape of `AuthClaims`, `JsonValue`, `JsonObject`, `SignOptions` and `VerifyOptions`, in both directions.

## How to get to it (user POV)

- `const token = await SignRaw({ userId: 123 }, { expiresIn: "1h" })`, then `const claims = await ValidateRaw(token, { maxAge: "30m" })` in a project that loads a provider such as auth-jwt.

## Driving it with antelopejs-verify

```bash
pnpm exec antelopejs-verify journey "$RUN" tokens
```

## Gotchas

- The provider is a stand-in: signature checks, expiry and token format are the provider's, so these journeys prove what this interface sends and returns, not what a real provider verifies.
