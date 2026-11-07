import { defineConfig } from "@antelopejs/interface-core/config";

export default defineConfig({
  name: "interface-auth-test",
  cacheFolder: ".antelope/cache",
  modules: {
    "auth-jwt": {
      source: { type: "local", path: "node_modules/@antelopejs/auth-jwt" },
      config: { secret: "test-secret-key-for-jwt" },
    },
    api: {
      source: {
        type: "package",
        package: "@antelopejs/api",
        version: "1.3.0",
      },
      config: {
        servers: [{ protocol: "http", host: "127.0.0.1", port: 5010 }],
        publicBaseUrl: "http://127.0.0.1:5010",
      },
    },
  },
  test: {
    folder: "dist/tests",
  },
});
