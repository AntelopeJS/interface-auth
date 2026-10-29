# Feature map

One file per feature. `covers:` lists the source globs it owns, `docs:` the pages a verdict judges, `journeys:` the journeys it runs, and `seeded-breaks/<feature>.patch` the break its journeys must catch. `pnpm exec antelopejs-verify map` checks that every user-facing file is covered.

| Feature | What the user does | Journeys |
|---|---|---|
| [tokens](tokens.md) | A module signs data into a token and verifies a token back into its claims through the provider. | sign-and-verify, token-types |
| [cookies](cookies.md) | A handler signs data and attaches it to the HTTP response as the authentication cookie. | sign-server-response, cookie-types |
| [request-auth](request-auth.md) | A controller requires authentication on a parameter, a property or a class and receives the verified claims. | default-source, check-authentication, auth-decorators, request-types |
| [smoke](smoke.md) | The fixed journeys every verdict runs: load the packed interface with a stub provider and call every function. | every-function, minor-bump |
