import { equal } from "@antelopejs/tooling-configs/verify";
import type { InterfaceHooks } from "@antelopejs/tooling-configs/verify";

import type * as AuthInterface from "../../../src/index.ts";

type PlainJson = Parameters<typeof equal>[2];

/** Narrows a JSON value to its object member: every other member is a primitive, `null` or an array. */
function isJsonObject(value: AuthInterface.JsonValue): value is AuthInterface.JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Copies a value of the interface's JSON types into the pack's, dropping the `undefined` members the interface allows. */
function plain(value: AuthInterface.JsonValue): PlainJson {
  if (Array.isArray(value)) return value.map(plain);
  if (!isJsonObject(value)) return value;
  return Object.fromEntries(Object.entries(value).flatMap(([key, member]) => (member === undefined ? [] : [[key, plain(member)] as const])));
}

/** The plain functions the consumer calls through core, each with the value it must resolve to. */
export const CALLS: NonNullable<InterfaceHooks<typeof AuthInterface>["calls"]> = {
  ".:ValidateRaw": {
    call: async (api) => plain(await api.ValidateRaw("tok", { maxAge: "1h" })),
    expect: { stub: ".:internal.Verify", args: ["tok", { maxAge: "1h" }] },
  },
  ".:SignRaw": { call: (api) => api.SignRaw({ userId: 1 }, { expiresIn: "1h" }), expect: { stub: ".:internal.Sign", args: [{ userId: 1 }, { expiresIn: "1h" }] } },
  ".:SignServerResponse": {
    call: async (api) => {
      const headers: Record<string, string> = {};
      // SAFETY: SignServerResponse only calls setHeader on the response.
      const res = { setHeader: (name: string, value: string) => void (headers[name] = value) } as never;
      const returned = await api.SignServerResponse(res, "payload", undefined, { httpOnly: true });
      return { headers, same: returned === res };
    },
    expect: { headers: { "Set-Cookie": "ANTELOPEJS_AUTH=[object Object]; httpOnly" }, same: true },
  },
  ".:CreateAuthDecorator": { call: async (api) => api.CreateAuthDecorator({})().length, expect: 3 },
  ".:Authentication": { call: async (api) => api.Authentication().length, expect: 3 },
  ".:internal.defaultSource": {
    // SAFETY: defaultSource reads only the headers of the request.
    call: async (api) => api.internal.defaultSource({ headers: { cookie: "ANTELOPEJS_AUTH=c" } } as never, {} as never) ?? null,
    expect: "c",
  },
  ".:internal.defaultAuthenticator": {
    call: async (api) => plain(await api.internal.defaultAuthenticator("tok", {})),
    expect: { stub: ".:internal.Verify", args: ["tok", {}] },
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
