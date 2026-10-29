import { expect } from "chai";
import { IncomingMessage, ServerResponse } from "node:http";
import { Socket } from "node:net";
import { ImplementInterface } from "@antelopejs/interface-core";
import { SignRaw, SignServerResponse, ValidateRaw, internal } from "..";

const signedToken = "signed-token";
const signCalls: Parameters<typeof internal.Sign>[] = [];
const verifyCalls: Parameters<typeof internal.Verify>[] = [];
let verifyOutcome: () => Awaited<ReturnType<typeof internal.Verify>>;

function requestWith(headers: Record<string, string>): IncomingMessage {
  const request = new IncomingMessage(new Socket());
  Object.assign(request.headers, headers);
  return request;
}

function newResponse(): ServerResponse {
  return new ServerResponse(new IncomingMessage(new Socket()));
}

function resetProviderState(): void {
  signCalls.length = 0;
  verifyCalls.length = 0;
  verifyOutcome = () => ({});
}

function implementProviders(): void {
  ImplementInterface(
    { Sign: internal.Sign, Verify: internal.Verify },
    {
      Sign: async (...args) => {
        signCalls.push(args);
        return signedToken;
      },
      Verify: async (...args) => {
        verifyCalls.push(args);
        return verifyOutcome();
      },
    },
  );
}

describe("Auth interface built from this repository", () => {
  before(implementProviders);

  beforeEach(resetProviderState);

  it("SignRaw hands the payload and options to the Sign provider", async () => {
    const token = await SignRaw({ userId: "u1" }, { expiresIn: "1h" });

    expect(token).to.equal(signedToken);
    expect(signCalls).to.deep.equal([[{ userId: "u1" }, { expiresIn: "1h" }]]);
  });

  it("ValidateRaw returns the payload of the Verify provider", async () => {
    verifyOutcome = () => ({ name: "Bob" });

    const payload = await ValidateRaw("the-token", { maxAge: "1h" });

    expect(payload).to.deep.equal({ name: "Bob" });
    expect(verifyCalls).to.deep.equal([["the-token", { maxAge: "1h" }]]);
  });

  it("ValidateRaw rejects with the error of the Verify provider", async () => {
    const failure = new Error("rejected by the provider");
    verifyOutcome = () => {
      throw failure;
    };
    let caught: unknown;

    try {
      await ValidateRaw("bad-token");
    } catch (error) {
      caught = error;
    }

    expect(caught).to.equal(failure);
  });
});

describe("Auth helpers built from this repository", () => {
  before(implementProviders);

  beforeEach(resetProviderState);

  it("set-cookie uses standalone boolean directives", async () => {
    const response = newResponse();

    await SignServerResponse(
      response,
      { userId: "user-7" },
      { expiresIn: "1h" },
      { httpOnly: true },
    );

    const setCookieHeader = response.getHeader("set-cookie");
    expect(setCookieHeader).to.be.a("string");
    expect(setCookieHeader).to.match(/^ANTELOPEJS_AUTH=/);
    expect(setCookieHeader).to.match(/httpOnly/);
    expect(setCookieHeader).to.not.match(/httpOnly=true/);
  });

  it("SignServerResponse serializes cookie attributes literally and omits false ones", async () => {
    const bare = newResponse();
    const attributed = newResponse();

    await SignServerResponse(bare, { userId: "u1" });
    await SignServerResponse(attributed, { userId: "u1" }, undefined, {
      path: "/",
      maxAge: 60,
      secure: true,
      httpOnly: false,
    });

    expect(bare.getHeader("set-cookie")).to.equal(
      `ANTELOPEJS_AUTH=${signedToken}`,
    );
    expect(attributed.getHeader("set-cookie")).to.equal(
      `ANTELOPEJS_AUTH=${signedToken}; path=/; maxAge=60; secure`,
    );
  });

  it("defaultSource reads the header first and the cookie otherwise", () => {
    const response = newResponse();
    const headerAndCookie = requestWith({
      "x-antelopejs-auth": "from-header",
      cookie: "ANTELOPEJS_AUTH=from-cookie",
    });
    const cookieOnly = requestWith({
      cookie: "other=1; ANTELOPEJS_AUTH=from-cookie; more=2",
    });

    expect(internal.defaultSource(headerAndCookie, response)).to.equal(
      "from-header",
    );
    expect(internal.defaultSource(cookieOnly, response)).to.equal(
      "from-cookie",
    );
    expect(internal.defaultSource(requestWith({}), response)).to.equal(
      undefined,
    );
  });

  it("CheckAuthentication verifies through the Verify provider and applies the validator", async () => {
    verifyOutcome = () => ({ id: 1 });
    const request = requestWith({ "x-antelopejs-auth": "the-token" });

    const callbacks = {
      source: internal.defaultSource,
      authenticator: ValidateRaw,
      authenticatorOptions: {},
      validator: undefined,
    };

    const plain = await internal.CheckAuthentication(
      request,
      newResponse(),
      callbacks,
    );
    const validated = await internal.CheckAuthentication(
      request,
      newResponse(),
      {
        ...callbacks,
        validator: (claims) => ({ claims, validated: true }),
      },
    );

    expect(plain).to.deep.equal({ id: 1 });
    expect(validated).to.deep.equal({ claims: { id: 1 }, validated: true });
    expect(verifyCalls).to.deep.equal([
      ["the-token", {}],
      ["the-token", {}],
    ]);
  });
});
