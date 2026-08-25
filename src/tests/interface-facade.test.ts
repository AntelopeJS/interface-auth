import assert from "node:assert";
import type { IncomingMessage, ServerResponse } from "node:http";
import * as Api from "@antelopejs/interface-api";
import {
  AmbiguousProviderError,
  GetInterfaceProxyIdentity,
} from "@antelopejs/interface-core";
import { CreateInterfaceFacade } from "@antelopejs/interface-core/facades";
import {
  type ModuleExecutionContext,
  RunWithModuleContext,
} from "@antelopejs/interface-core/modules";
import * as Auth from "../index";

function providerContext(provider: string): ModuleExecutionContext {
  return {
    module: provider,
    owner: `${provider}#1`,
    provider,
  };
}

function consumerContext(
  owner: string,
  authProvider: string,
  apiProvider: string,
): ModuleExecutionContext {
  const verifyIdentity = GetInterfaceProxyIdentity(Auth.internal.Verify.proxy);
  const routesIdentity = GetInterfaceProxyIdentity(Api.routesProxy);
  assert(verifyIdentity);
  assert(routesIdentity);
  return {
    module: "auth-consumer",
    owner,
    providerRoutes: {
      [verifyIdentity]: authProvider,
      [routesIdentity]: apiProvider,
    },
  };
}

function requestWithToken(token: string): IncomingMessage {
  return {
    headers: { "x-antelopejs-auth": token },
  } as unknown as IncomingMessage;
}

describe("Auth interface facade", () => {
  it("routes default Authentication through the consumer provider after await", async () => {
    const authLeaseA = RunWithModuleContext(
      providerContext("auth-provider-a"),
      () =>
        Auth.internal.Verify.proxy.onCall(async (token) => `a:${token}`, true),
    );
    const authLeaseB = RunWithModuleContext(
      providerContext("auth-provider-b"),
      () =>
        Auth.internal.Verify.proxy.onCall(async (token) => `b:${token}`, true),
    );
    const registered: Api.RouteHandler[] = [];
    const apiLease = RunWithModuleContext(providerContext("api-provider"), () =>
      Api.routesProxy.onHandlers(
        (_id, handler) => registered.push(handler),
        () => {},
        true,
      ),
    );
    const contextA = consumerContext(
      "auth-consumer#old",
      "auth-provider-a",
      "api-provider",
    );
    const contextB = consumerContext(
      "auth-consumer#new",
      "auth-provider-b",
      "api-provider",
    );
    const authA = CreateInterfaceFacade(Auth, contextA);
    const authB = CreateInterfaceFacade(Auth, contextB);
    const apiA = CreateInterfaceFacade(Api, contextA);
    const apiB = CreateInterfaceFacade(Api, contextB);
    class ControllerA {
      handler(authenticated: unknown) {
        return authenticated;
      }
    }
    class ControllerB {
      handler(authenticated: unknown) {
        return authenticated;
      }
    }
    const targetA = ControllerA.prototype;
    const targetB = ControllerB.prototype;
    const descriptorA = Object.getOwnPropertyDescriptor(targetA, "handler");
    const descriptorB = Object.getOwnPropertyDescriptor(targetB, "handler");
    assert(descriptorA);
    assert(descriptorB);

    try {
      const ambiguous = await Auth.ValidateRaw("token").then(
        () => undefined,
        (error: unknown) => error,
      );
      assert(ambiguous instanceof AmbiguousProviderError);

      authA.Authentication()(targetA, "handler", 0);
      authB.Authentication()(targetB, "handler", 0);
      apiA.Get("/auth/a")(targetA, "handler", descriptorA);
      apiB.Get("/auth/b")(targetB, "handler", descriptorB);

      assert.equal(registered.length, 2);
      assert.strictEqual(registered[0].callback, targetA.handler);
      assert.strictEqual(registered[1].callback, targetB.handler);
      const providerA = registered[0].parameters[0]?.provider;
      const providerB = registered[1].parameters[0]?.provider;
      assert(providerA);
      assert(providerB);

      await Promise.resolve();

      const response = {} as ServerResponse;
      assert.equal(
        await providerA({
          rawRequest: requestWithToken("token-a"),
          rawResponse: response,
        } as Api.RequestContext),
        "a:token-a",
      );
      assert.equal(
        await providerB({
          rawRequest: requestWithToken("token-b"),
          rawResponse: response,
        } as Api.RequestContext),
        "b:token-b",
      );
      assert.strictEqual(apiA.HTTPResult, Api.HTTPResult);
      assert.strictEqual(apiB.HTTPResult, Api.HTTPResult);
    } finally {
      Api.routesProxy.unregisterOwner(contextA.owner as string);
      Api.routesProxy.unregisterOwner(contextB.owner as string);
      Api.routesProxy.detach(apiLease);
      Auth.internal.Verify.proxy.detach(authLeaseA);
      Auth.internal.Verify.proxy.detach(authLeaseB);
    }
  });
});
