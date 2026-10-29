---
covers:
  - src/index.ts
docs:
  - docs/1.introduction.md
  - docs/3.token-handling.md
journeys:
  - sign-server-response
  - cookie-types
---

# Cookies

A handler calls `SignServerResponse(res, data, signOptions?, cookieOptions?)` to sign data and set it as the `ANTELOPEJS_AUTH` cookie on the response, replacing any `Set-Cookie` header already there. The response is returned and not sent.

## Sub-features

- `sign-server-response`: on a real `http.ServerResponse`, with a stand-in provider signing: the header is `ANTELOPEJS_AUTH=<token>` with no attribute by default, an earlier `Set-Cookie` is replaced, the same response object comes back, the response is not sent, the sign options reach the provider, and cookie options are written as documented (keys literally, `true` as a bare directive, `false` and `undefined` omitted, other values with `String(value)`, no trailing separator when every option is omitted).
- `cookie-types`: a probe compiled in strict mode against the packed declarations pins the parameters and answer of `SignServerResponse` and the exact shape of `CookieOptions`.

## How to get to it (user POV)

- `await SignServerResponse(res, { userId: 123 }, { expiresIn: "1h" }, { httpOnly: true, secure: true, path: "/" })` in a login handler.

## Driving it with antelopejs-verify

```bash
pnpm exec antelopejs-verify journey "$RUN" cookies
```

## Gotchas

- `maxAge`, `signed` and `expires` are written literally (`maxAge=60`, not `Max-Age`), as the docs say; the journey pins that behaviour, so changing the serializer is a visible, documented change.
