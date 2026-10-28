import { expect } from "chai";
import { HTTPResult } from "@antelopejs/interface-api";
import { SignRaw, ValidateRaw } from "@antelopejs/interface-auth";

interface TestUser {
  id: string;
  name: string;
  email: string;
  password: string;
}

interface TestUsers {
  default: Omit<TestUser, "id">;
  alternate: Omit<TestUser, "id">;
}

const testUsers: TestUsers = {
  default: {
    name: "Bob",
    email: "bob@email.com",
    password: "very-secure-qwerty123",
  },
  alternate: {
    name: "Alice",
    email: "alice@email.com",
    password: "very-secure-qwerty123",
  },
};

describe("JWT Authentication Tests", () => {
  it("jwt token is valid", async () => {
    const userData = testUsers.default;
    const token = await SignRaw(userData, { expiresIn: "1h" });

    const verifiedData = await ValidateRaw<TestUser>(token);

    expect(verifiedData).to.be.an("object");
    expect(verifiedData).to.have.property("name", userData.name);
    expect(verifiedData).to.have.property("email", userData.email);
    expect(verifiedData).to.have.property("password", userData.password);
  });

  it("jwt token is invalid", async () => {
    const invalidToken = "invalid.jwt.token";

    try {
      await ValidateRaw<TestUser>(invalidToken);
      expect.fail("Should have thrown an error for invalid token");
    } catch (error) {
      expect(error).to.be.instanceOf(HTTPResult);
    }
  });

  it("jwt token is expired", async () => {
    const userData = testUsers.default;
    const token = await SignRaw(userData, { expiresIn: "1ms" });

    await new Promise((resolve) => setTimeout(resolve, 10));

    try {
      await ValidateRaw<TestUser>(token);
      expect.fail("Should have thrown an error for expired token");
    } catch (error) {
      expect(error).to.be.instanceOf(HTTPResult);
    }
  });
});
