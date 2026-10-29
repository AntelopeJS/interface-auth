import { equal, interrupted } from "@antelopejs/tooling-configs/verify";
import { ImplementInterface } from "@antelopejs/interface-core";
import type { HttpResult, InterfaceHooks, Journey, VerifyConfig } from "@antelopejs/tooling-configs/verify";

import type * as AuthInterface from "../../../src/index.ts";

/** What `internal.Sign` receives. */
type SignData = Parameters<typeof AuthInterface.SignRaw>[0];

/** What the stand-in provider answers to `internal.Sign`: a token naming its data. */
const signed = (data: SignData): string => `tok:${JSON.stringify(data)}`;

/** What the stand-in provider answers to `internal.Verify`: the claims it was asked to verify. */
const verified = (token: string | undefined, options: AuthInterface.VerifyOptions | undefined) => ({ verified: token ?? null, options: options ?? null });

/** What the driver module answers to a route, parsed. */
interface Reply {
  ok: boolean;
  value: HttpResult["json"];
}

/** The setup every scenario shares: the packed interface, a recording stand-in provider behind `internal.Sign` and `internal.Verify`, and small helpers. */
const SCENARIO_PRELUDE = `
const [dist, repo] = process.argv.slice(2);
const { createRequire } = require("node:module");
const http = require("node:http");
const fromRepo = createRequire(repo + "/");
const auth = require(dist);
const api = fromRepo("@antelopejs/interface-api");
const core = fromRepo("@antelopejs/interface-core");
const log = [];
auth.internal.Sign.proxy.onCall(async (data, options) => {
  log.push(["sign", data, options ?? null]);
  return "tok:" + (typeof data === "string" ? data : JSON.stringify(data));
}, true);
auth.internal.Verify.proxy.onCall(async (token, options) => {
  log.push(["verify", token ?? null, options ?? null]);
  if (token === undefined || token === "bad") throw new Error("invalid token");
  return token === "str" ? "plain" : { sub: token, options: options ?? null };
}, true);
const rejection = async (promise) => { try { await promise; return null; } catch (error) { return error.message; } };
const request = (headers) => ({ headers });
const response = () => new http.ServerResponse(new http.IncomingMessage(null));
`;

const SCENARIO_TAIL = `
main().then((out) => { console.log(JSON.stringify(out, (key, value) => (value === undefined ? null : value))); process.exit(0); }, (error) => { console.error(error); process.exit(1); });
`;

/** The probe header: `Assert<Identical<A, B>>` fails to compile unless A and B are the same type, so an added optional field or a widening to `any` is caught. */
const PROBE_HEADER = `
type Identical<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type Assert<T extends true> = T;
type Answer<F extends (...args: never[]) => unknown> = Awaited<ReturnType<F>>;
`;

/** Runs a scenario against the packed interface and a recording stand-in provider, then checks what it printed against the documented behaviour. */
function scenario(title: string, body: string, printed: string): Journey {
  return {
    title,
    entryPoint: "the packed interface driven from a Node process with a stand-in provider attached to internal.Sign and internal.Verify",
    async run(context) {
      const file = `${context.work}/scenario.js`;
      context.edit("write the scenario", file, `${SCENARIO_PRELUDE}\nasync function main() {\n${body}\n}\n${SCENARIO_TAIL}`);
      const ran = await context.command("run the scenario", "node", [file, `${context.repo}/dist/index.js`, context.repo], { timeoutMs: 60_000 });
      context.expect(ran.folder, [
        { name: "the scenario ended cleanly", pass: ran.exitCode === 0, detail: ran.stderr.slice(-300) },
        equal("the answers are what the docs promise", ran.stdout.trim().split("\n").at(-1) ?? "", printed),
      ]);
    },
  };
}

/** Compiles a probe against the packed declarations in the consumer's strict mode. */
function declared(title: string, probe: string): Journey {
  return {
    title,
    entryPoint: "a TypeScript consumer compiling against the packed declarations",
    async run(context) {
      const file = `${context.work}/probe.ts`;
      const imports = `import * as Api from "${context.repo}/dist/index";\nimport type { IncomingMessage, ServerResponse } from "node:http";`;
      await context.command("link the repository's dependencies", "ln", ["-s", `${context.repo}/node_modules`, `${context.work}/node_modules`]);
      context.edit("write the shape probe", file, `${imports}\n${PROBE_HEADER}\n${probe}`);
      const compiled = await context.command("compile the shape probe", "node", [
        `${context.repo}/node_modules/typescript/bin/tsc`,
        "--noEmit",
        "--strict",
        "--skipLibCheck",
        "--target",
        "es2022",
        "--module",
        "commonjs",
        "--moduleResolution",
        "node",
        "--typeRoots",
        `${context.repo}/node_modules/@types`,
        "--types",
        "node",
        file,
      ]);
      context.expect(compiled.folder, [{ name: "every export has the documented shape", pass: compiled.exitCode === 0, detail: compiled.stdout.slice(0, 600) }]);
    },
  };
}

/** Parses the body of a driver answer: the value on success, the error otherwise. */
function reply(body: string): Reply {
  const parsed: { ok: boolean; value?: HttpResult["json"]; error?: HttpResult["json"] } = JSON.parse(body);
  return { ok: parsed.ok, value: parsed.ok ? parsed.value : parsed.error };
}

/** Every runtime function of the packed interface, the `internal` namespace included, by path. */
const RUNTIME_FUNCTIONS = [
  "Authentication",
  "CreateAuthDecorator",
  "SignRaw",
  "SignServerResponse",
  "ValidateRaw",
  "internal.CheckAuthentication",
  "internal.Sign",
  "internal.Verify",
  "internal.defaultAuthenticator",
  "internal.defaultSource",
];

/** The proxies a consumer reaches through core, with the arguments sent and what the stub provider answers. */
const PROXY_CALLS = [
  { path: ["internal", "Sign"], args: ["payload"], expect: 'tok:"payload"' },
  { path: ["internal", "Verify"], args: ["tok", { maxAge: 1 }], expect: { verified: "tok", options: { maxAge: 1 } } },
];

/**
 * The shared `every-function` and `minor-bump` journeys read the declarations with `types: []`, which fails on the Node built-ins `node:http` that
 * these declarations import until tooling-configs resolves them. This journey lists the runtime functions of the packed interface and calls
 * each one through core in `ajs project dev` next to the stub provider.
 */
const coreFunctions: Journey = {
  title: "every runtime function of the packed interface answers through core from a stub provider",
  entryPoint: "a consumer module calling the packed interface in `ajs project dev`",
  async run(context) {
    const file = `${context.work}/exports.js`;
    context.edit(
      "write the export listing",
      file,
      `const auth = require(process.argv[2]);
const names = (object, prefix) => Object.keys(object).filter((key) => typeof object[key] === "function").map((key) => prefix + key);
console.log(JSON.stringify([...names(auth, ""), ...names(auth.internal, "internal.")].sort()));
`,
    );
    const listed = await context.command("list the runtime functions", "node", [file, `${context.repo}/dist/index.js`]);
    context.expect(listed.folder, [equal("the packed interface exports exactly the documented functions", listed.stdout.trim(), JSON.stringify(RUNTIME_FUNCTIONS))], { critical: true });
    const app = await context.dev("ajs project dev", context.fixture());
    for (const [path, call] of Object.entries(CALLS)) {
      const answer = await context.http(`call ${path}`, `http://127.0.0.1:${app.port}/hook`, { method: "POST", body: JSON.stringify({ path }) });
      const got = reply(answer.body);
      context.expect(answer.folder, [
        { name: `${path} resolved through core`, pass: got.ok, detail: JSON.stringify(got.value) },
        equal(`${path} returned the value verify.config.ts expects`, got.value, call.expect),
      ]);
    }
    for (const proxy of PROXY_CALLS) {
      const name = `internal.${proxy.path[1]}`;
      const answer = await context.call(`call ${name}`, app, { path: proxy.path, args: proxy.args });
      context.expect(answer.folder, [
        { name: `${name} resolved through core`, pass: answer.ok, detail: JSON.stringify(answer.value) },
        equal(`${name} returned what the stub provider answers`, answer.value, proxy.expect),
      ]);
    }
    const stopped = await context.stop("SIGINT", app);
    context.expect(stopped.folder, [interrupted(stopped)]);
  },
};

const SIGN_VERIFY_BODY = `
  const token = await auth.SignRaw({ userId: 123, role: "admin" }, { expiresIn: "1h", notBefore: 5 });
  const text = await auth.SignRaw("plain-data");
  const claims = await auth.ValidateRaw(token, { maxAge: "30m", ignoreExpiration: false });
  const string = await auth.ValidateRaw("str");
  const missing = await rejection(auth.ValidateRaw());
  const rejected = await rejection(auth.ValidateRaw("bad", { ignoreNotBefore: true }));
  return { token, text, claims, string, missing, rejected, log };
`;

const COOKIE_BODY = `
  const expires = new Date(0);
  const first = response();
  first.setHeader("Set-Cookie", "old=1");
  const returned = await auth.SignServerResponse(first, { userId: 1 });
  const full = response();
  await auth.SignServerResponse(full, "s", { expiresIn: "8h" }, { maxAge: 60, signed: true, expires, httpOnly: true, path: "/", domain: "example.test", secure: true });
  const dropped = response();
  await auth.SignServerResponse(dropped, "s", undefined, { httpOnly: false, secure: undefined });
  const mixed = response();
  await auth.SignServerResponse(mixed, "s", undefined, { httpOnly: true, secure: false, path: "/a" });
  return {
    bare: first.getHeader("Set-Cookie"),
    same: returned === first,
    sent: first.headersSent,
    full: full.getHeader("Set-Cookie") === "ANTELOPEJS_AUTH=tok:s; maxAge=60; signed; expires=" + String(expires) + "; httpOnly; path=/; domain=example.test; secure",
    dropped: dropped.getHeader("Set-Cookie"),
    mixed: mixed.getHeader("Set-Cookie"),
    log,
  };
`;

const SOURCE_BODY = `
  const source = auth.internal.defaultSource;
  const res = {};
  return {
    header: source(request({ "x-antelopejs-auth": "h" }), res),
    array: source(request({ "x-antelopejs-auth": ["a", "b"] }), res),
    headerOverCookie: source(request({ "x-antelopejs-auth": "h", cookie: "ANTELOPEJS_AUTH=c" }), res),
    emptyHeader: source(request({ "x-antelopejs-auth": "", cookie: "ANTELOPEJS_AUTH=c" }), res),
    cookie: source(request({ cookie: "ANTELOPEJS_AUTH=c" }), res),
    cookieAmong: source(request({ cookie: "a=1; ANTELOPEJS_AUTH=c; b=2" }), res),
    lookalike: source(request({ cookie: "XANTELOPEJS_AUTH=z; MY_ANTELOPEJS_AUTH=y" }), res),
    authorization: source(request({ authorization: "Bearer t" }), res),
    none: source(request({}), res),
  };
`;

const PIPELINE_BODY = `
  const check = auth.internal.CheckAuthentication;
  const req = request({});
  const res = {};
  const steps = [];
  const callbacks = (over = {}) => ({
    source: (r, s) => { steps.push(["source", r === req, s === res]); return "tok"; },
    authenticator: async (data, options) => { steps.push(["authenticator", data, options]); return { user: data }; },
    authenticatorOptions: { maxAge: 5 },
    validator: undefined,
    ...over,
  });
  const plain = await check(req, res, callbacks());
  const plainSteps = steps.splice(0);
  const validated = await check(req, res, callbacks({ validator: (claims) => { steps.push(["validator", claims]); return { injected: claims.user }; } }));
  const validatedSteps = steps.splice(0);
  const falsy = await check(req, res, callbacks({ validator: () => false }));
  steps.length = 0;
  const denied = await rejection(check(req, res, callbacks({ validator: () => { throw new Error("denied"); } })));
  const refused = await rejection(check(req, res, callbacks({ authenticator: async () => { throw new Error("no token"); }, validator: () => { steps.push(["validator"]); return 1; } })));
  const refusedSteps = steps.splice(0);
  const missing = await check(req, res, callbacks({ source: () => undefined, authenticator: async (data) => ({ saw: data }) }));
  return { plain, plainSteps, validated, validatedSteps, falsy, denied, refused, refusedSteps, missing, defaultIsValidateRaw: auth.internal.defaultAuthenticator === auth.ValidateRaw };
`;

const DECORATOR_BODY = `
  const { ControllerMeta, computeParameter } = api;
  const meta = (cls) => core.GetMetadata(cls, ControllerMeta);
  const context = (headers) => ({ rawRequest: request(headers), rawResponse: {} });
  const param = (cls, key, index) => meta(cls).computed_params[key][index];
  const run = (cls, key, index, headers) => computeParameter(context(headers), param(cls, key, index), {});

  class Plain extends api.Controller("/plain") {}
  auth.Authentication()(Plain.prototype, "handler", 0);
  const defaults = await run(Plain, "handler", 0, { "x-antelopejs-auth": "abc" });
  const defaultsLog = log.splice(0);
  const missing = await rejection(run(Plain, "handler", 0, {}));
  const missingLog = log.splice(0);

  const Configured = auth.CreateAuthDecorator({ authenticatorOptions: { maxAge: 9 }, validator: (claims) => ({ configured: claims.sub }) });
  class Validators extends api.Controller("/validators") {}
  Configured()(Validators.prototype, "configured", 0);
  Configured((claims) => ({ inline: claims.sub }))(Validators.prototype, "inline", 0);
  const configured = await run(Validators, "configured", 0, { "x-antelopejs-auth": "t1" });
  const inline = await run(Validators, "inline", 0, { "x-antelopejs-auth": "t2" });
  const validatorLog = log.splice(0);

  const Key = auth.CreateAuthDecorator({
    source: (req) => req.headers["x-api-key"],
    authenticator: async (key) => ({ key }),
  });
  class Custom extends api.Controller("/custom") {}
  Key()(Custom.prototype, "handler", 0);
  const custom = await run(Custom, "handler", 0, { "x-api-key": "k1", "x-antelopejs-auth": "ignored" });
  const customLog = log.splice(0);

  class Property extends api.Controller("/property") {}
  auth.Authentication()(Property.prototype, "user");
  const property = await computeParameter(context({ cookie: "ANTELOPEJS_AUTH=ck" }), meta(Property).computed_props.user, {});

  class Whole extends api.Controller("/whole") {}
  auth.Authentication()(Whole);
  const symbols = Object.getOwnPropertySymbols(meta(Whole).computed_props);
  const whole = await computeParameter(context({ "x-antelopejs-auth": "w" }), meta(Whole).computed_props[symbols[0]], {});

  return { defaults, defaultsLog, missing, missingLog, configured, inline, validatorLog, custom, customLog, property, symbols: symbols.map((symbol) => symbol.description), whole };
`;

const TOKEN_TYPES = `
type _Sign = Assert<Identical<Parameters<typeof Api.SignRaw>, [data: string | Buffer | Api.JsonObject, options?: Api.SignOptions]>>;
type _SignAnswer = Assert<Identical<Answer<typeof Api.SignRaw>, string>>;
type _Validate = Assert<Identical<Parameters<typeof Api.ValidateRaw>, [token?: string, options?: Api.VerifyOptions]>>;
type _ValidateAnswer = Assert<Identical<Answer<typeof Api.ValidateRaw>, string | Api.JsonObject>>;
type _Claims = Assert<Identical<Api.AuthClaims, string | Api.JsonObject>>;
type _Value = Assert<Identical<Api.JsonValue, string | number | boolean | null | Api.JsonValue[] | Api.JsonObject>>;
type _Object = Assert<Identical<Api.JsonObject, { [key: string]: Api.JsonValue | undefined }>>;
type _SignOptions = Assert<Identical<Api.SignOptions, { expiresIn?: string | number; notBefore?: string | number }>>;
type _VerifyOptions = Assert<Identical<Api.VerifyOptions, { ignoreExpiration?: boolean; ignoreNotBefore?: boolean; maxAge?: string | number }>>;
`;

const COOKIE_TYPES = `
type _Cookie = Assert<Identical<Parameters<typeof Api.SignServerResponse>, [res: ServerResponse, data: string | Buffer | Api.JsonObject, signOptions?: Api.SignOptions, cookieOptions?: Api.CookieOptions]>>;
type _CookieAnswer = Assert<Identical<Answer<typeof Api.SignServerResponse>, ServerResponse>>;
type _Options = Assert<Identical<Api.CookieOptions, { maxAge?: number; signed?: boolean; expires?: Date; httpOnly?: boolean; path?: string; domain?: string; secure?: boolean }>>;
`;

const REQUEST_TYPES = `
type _Source = Assert<Identical<Api.AuthSource, (req: IncomingMessage, res: ServerResponse) => string | undefined>>;
type _Verifier = Assert<Identical<Api.AuthVerifier, (data?: string, options?: Api.VerifyOptions) => Promise<Api.AuthClaims> | Api.AuthClaims>>;
type _VerifierOf = Assert<Identical<Api.AuthVerifier<{ id: number }>, (data?: string, options?: Api.VerifyOptions) => Promise<{ id: number }> | { id: number }>>;
type _Validator = Assert<Identical<Api.AuthValidator, (data: Api.AuthClaims) => unknown>>;
type _ValidatorOf = Assert<Identical<Api.AuthValidator<{ id: number }, boolean>, (data: { id: number }) => Promise<boolean> | boolean>>;

const Default = Api.CreateAuthDecorator({ validator: (claims) => { type _Claims = Assert<Identical<typeof claims, Api.AuthClaims>>; return claims; } });
type _Default = Assert<Identical<Parameters<typeof Default>, [validator?: Api.AuthValidator<Api.AuthClaims, Api.AuthClaims>]>>;
const Typed = Api.CreateAuthDecorator({ authenticator: async (token?: string) => ({ id: token?.length ?? 0 }), validator: (user) => user.id > 0 });
type _Typed = Assert<Identical<Parameters<typeof Typed>, [validator?: Api.AuthValidator<{ id: number }, boolean>]>>;
type _Authentication = Assert<Identical<Parameters<typeof Api.Authentication>, [validator?: Api.AuthValidator<Api.AuthClaims, unknown>]>>;
type _Decorators = Assert<Identical<ReturnType<typeof Typed>, ReturnType<typeof Api.Authentication>>>;
`;

/** The plain functions the consumer calls through core, each with the value it must resolve to. */
const CALLS: NonNullable<InterfaceHooks<typeof AuthInterface>["calls"]> = {
  ".:ValidateRaw": {
    call: (api) => api.ValidateRaw("tok", { maxAge: "1h" }),
    expect: { verified: "tok", options: { maxAge: "1h" } },
  },
  ".:SignRaw": { call: (api) => api.SignRaw({ userId: 1 }, { expiresIn: "1h" }), expect: 'tok:{"userId":1}' },
  ".:SignServerResponse": {
    call: async (api) => {
      const headers: Record<string, string> = {};
      // SAFETY: SignServerResponse only calls setHeader on the response.
      const res = { setHeader: (name: string, value: string) => void (headers[name] = value) } as never;
      const returned = await api.SignServerResponse(res, "payload", undefined, { httpOnly: true });
      return { headers, same: returned === res };
    },
    expect: { headers: { "Set-Cookie": 'ANTELOPEJS_AUTH=tok:"payload"; httpOnly' }, same: true },
  },
  ".:CreateAuthDecorator": { call: (api) => api.CreateAuthDecorator({})().length, expect: 3 },
  ".:Authentication": { call: (api) => api.Authentication().length, expect: 3 },
  ".:internal.defaultSource": {
    // SAFETY: defaultSource reads only the headers of the request.
    call: (api) => api.internal.defaultSource({ headers: { cookie: "ANTELOPEJS_AUTH=c" } } as never, {} as never) ?? null,
    expect: "c",
  },
  ".:internal.defaultAuthenticator": {
    call: async (api) => api.internal.defaultAuthenticator("tok", {}),
    expect: { verified: "tok", options: {} },
  },
  ".:internal.CheckAuthentication": {
    call: (api) =>
      api.internal.CheckAuthentication(
        // SAFETY: the source and the authenticator below never read the request.
        {} as never,
        // SAFETY: the source and the authenticator below never read the response.
        {} as never,
        { source: () => "t", authenticator: (data) => `verified:${data}`, authenticatorOptions: {}, validator: (claims) => `validated:${claims}` },
      ),
    expect: "validated:verified:t",
  },
};

const config: VerifyConfig<typeof AuthInterface> = {
  doors: {
    data: null,
    format: {
      globs: ["src/index.ts"],
      funnels: [],
      containments: ["cookies/sign-server-response", "request-auth/default-source"],
      why: "the x-antelopejs-auth header name, the ANTELOPEJS_AUTH cookie name and the cookie attribute syntax are what browsers and clients already hold",
    },
    contract: {
      globs: ["src/index.ts", "package.json"],
      funnels: [],
      containments: [],
      why: "SignRaw, ValidateRaw, SignServerResponse, CreateAuthDecorator, Authentication and their types are what every authenticating module imports",
    },
    outbound: null,
    exposure: null,
    publish: {
      globs: ["package.json", ".release-it.json", "changelogen.config.json", ".github/workflows/release.yml"],
      funnels: [],
      containments: [],
      why: "the package name and release workflow claim @antelopejs/interface-auth on npm",
    },
  },
  interface: {
    provide(api) {
      ImplementInterface(api, { internal: { Sign: signed, Verify: verified } });
    },
    calls: CALLS,
  },
  journeys: {
    "core-functions": coreFunctions,
    "sign-and-verify": scenario("SignRaw and ValidateRaw hand data, tokens and options to the provider and return what it answers, including a rejection", SIGN_VERIFY_BODY, '{"token":"tok:{\\"userId\\":123,\\"role\\":\\"admin\\"}","text":"tok:plain-data","claims":{"sub":"tok:{\\"userId\\":123,\\"role\\":\\"admin\\"}","options":{"maxAge":"30m","ignoreExpiration":false}},"string":"plain","missing":"invalid token","rejected":"invalid token","log":[["sign",{"userId":123,"role":"admin"},{"expiresIn":"1h","notBefore":5}],["sign","plain-data",null],["verify","tok:{\\"userId\\":123,\\"role\\":\\"admin\\"}",{"maxAge":"30m","ignoreExpiration":false}],["verify","str",null],["verify",null,null],["verify","bad",{"ignoreNotBefore":true}]]}'),
    "token-types": declared("SignRaw, ValidateRaw and the claim and option types have the documented shapes", TOKEN_TYPES),
    "sign-server-response": scenario("SignServerResponse sets the ANTELOPEJS_AUTH cookie, replaces Set-Cookie, writes cookie options literally and returns the unsent response", COOKIE_BODY, '{"bare":"ANTELOPEJS_AUTH=tok:{\\"userId\\":1}","same":true,"sent":false,"full":true,"dropped":"ANTELOPEJS_AUTH=tok:s","mixed":"ANTELOPEJS_AUTH=tok:s; httpOnly; path=/a","log":[["sign",{"userId":1},null],["sign","s",{"expiresIn":"8h"}],["sign","s",null],["sign","s",null]]}'),
    "cookie-types": declared("SignServerResponse and CookieOptions have the documented shapes", COOKIE_TYPES),
    "default-source": scenario("the default source prefers the header, then the cookie, and reads nothing else", SOURCE_BODY, '{"header":"h","array":"a","headerOverCookie":"h","emptyHeader":"","cookie":"c","cookieAmong":"c","lookalike":null,"authorization":null,"none":null}'),
    "check-authentication": scenario("the pipeline runs source, authenticator and validator in order and stops at the first throw", PIPELINE_BODY, '{"plain":{"user":"tok"},"plainSteps":[["source",true,true],["authenticator","tok",{"maxAge":5}]],"validated":{"injected":"tok"},"validatedSteps":[["source",true,true],["authenticator","tok",{"maxAge":5}],["validator",{"user":"tok"}]],"falsy":false,"denied":"denied","refused":"no token","refusedSteps":[["source",true,true],["authenticator","tok",{"maxAge":5}],["source",true,true]],"missing":{"saw":null},"defaultIsValidateRaw":true}'),
    "auth-decorators": scenario("decorators applied to a real Controller register a provider that authenticates a request through the pipeline", DECORATOR_BODY, '{"defaults":{"sub":"abc","options":{}},"defaultsLog":[["verify","abc",{}]],"missing":"invalid token","missingLog":[["verify",null,{}]],"configured":{"configured":"t1"},"inline":{"inline":"t2"},"validatorLog":[["verify","t1",{"maxAge":9}],["verify","t2",{"maxAge":9}]],"custom":{"key":"k1"},"customLog":[],"property":{"sub":"ck","options":{}},"symbols":["authentication-class-provider"],"whole":{"sub":"w","options":{}}}'),
    "request-types": declared("the callback types and decorator factories have the documented shapes", REQUEST_TYPES),
  },
};

export default config;
