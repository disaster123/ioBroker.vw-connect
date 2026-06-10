// @ts-nocheck
"use strict";

const { expect } = require("chai");
const { OAuthDeviceGrant, redactSecrets } = require("../lib/oauthDeviceGrant");
const {
  decodeBase64UrlJson,
  resolveSeatCupraUserId,
  getSeatCupraGarageUrl,
  getSeatCupraOlaHeaders,
} = require("../lib/seatCupra");

function response(status, data) {
  return { status, data };
}

describe("OAuthDeviceGrant", () => {
  it("sends client_id and scope in the device authorization body", async () => {
    let request;
    const grant = new OAuthDeviceGrant({
      clientId: "client-id",
      scope: "openid profile",
      httpClient: async (options) => {
        request = options;
        return response(200, {
          device_code: "device-code",
          user_code: "ABCD-EFGH",
          verification_uri: "https://example.test/device",
          expires_in: 300,
        });
      },
    });

    await grant.requestDeviceCode();
    const body = new URLSearchParams(request.data);
    expect(body.get("client_id")).to.equal("client-id");
    expect(body.get("scope")).to.equal("openid profile");
  });

  it("continues polling after authorization_pending", async () => {
    const replies = [
      response(400, { error: "authorization_pending" }),
      response(200, { access_token: "access", refresh_token: "refresh" }),
    ];
    let now = 0;
    const grant = new OAuthDeviceGrant({
      clientId: "client-id",
      scope: "openid",
      httpClient: async () => replies.shift(),
      sleep: async (ms) => { now += ms; },
      now: () => now,
    });

    const tokens = await grant.pollForTokens("device-code", { interval: 1, expiresIn: 30 });
    expect(tokens.access_token).to.equal("access");
  });

  it("adds five seconds to the interval after slow_down", async () => {
    const replies = [
      response(400, { error: "slow_down" }),
      response(200, { access_token: "access" }),
    ];
    const sleeps = [];
    let now = 0;
    const grant = new OAuthDeviceGrant({
      clientId: "client-id",
      scope: "openid",
      httpClient: async () => replies.shift(),
      sleep: async (ms) => { sleeps.push(ms); now += ms; },
      now: () => now,
    });

    await grant.pollForTokens("device-code", { interval: 2, expiresIn: 30 });
    expect(sleeps).to.deep.equal([2000, 7000]);
  });

  it("requires access_token but allows refresh_token to be absent", async () => {
    const debugMessages = [];
    const grant = new OAuthDeviceGrant({
      clientId: "client-id",
      scope: "openid",
      httpClient: async () => response(200, { access_token: "access" }),
      sleep: async () => {},
      logger: { debug: (message) => debugMessages.push(message) },
    });
    const tokens = await grant.pollForTokens("device-code", { interval: 1, expiresIn: 30 });
    expect(tokens.access_token).to.equal("access");
    expect(tokens.refresh_token).to.equal(undefined);
    expect(debugMessages[0]).to.include("refresh token present: false");
  });

  it("rejects a successful token response without access_token", async () => {
    const grant = new OAuthDeviceGrant({
      clientId: "client-id",
      scope: "openid",
      httpClient: async () => response(200, { refresh_token: "refresh" }),
      sleep: async () => {},
    });
    await expect(grant.pollForTokens("device-code", { interval: 1, expiresIn: 30 }))
      .to.be.rejectedWith("did not include access_token");
  });

  it("uses refresh_token grant and accepts a rotated refresh token", async () => {
    let request;
    const grant = new OAuthDeviceGrant({
      clientId: "client-id",
      scope: "openid",
      httpClient: async (options) => {
        request = options;
        return response(200, { access_token: "new-access", refresh_token: "new-refresh" });
      },
    });

    const tokens = await grant.refreshToken("old-refresh");
    const body = new URLSearchParams(request.data);
    expect(body.get("grant_type")).to.equal("refresh_token");
    expect(body.get("refresh_token")).to.equal("old-refresh");
    expect(tokens.refresh_token).to.equal("new-refresh");
  });
});


describe("SEAT/CUPRA user id resolution", () => {
  function jwt(payload) {
    const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
    return `${encode({ alg: "none" })}.${encode(payload)}.signature`;
  }

  it("decodes base64url JWT JSON and extracts sub before HTTP fallbacks", async () => {
    const token = jwt({ sub: "jwt-user" });
    expect(decodeBase64UrlJson(token.split(".")[1]).sub).to.equal("jwt-user");
    let httpCalls = 0;
    const userId = await resolveSeatCupraUserId({
      idToken: token,
      identityUserInfo: async () => { httpCalls++; return { sub: "identity-user" }; },
      olaUsers: async () => { httpCalls++; return { userId: "ola-user" }; },
    });
    expect(userId).to.equal("jwt-user");
    expect(httpCalls).to.equal(0);
  });

  it("falls back to identity-userinfo", async () => {
    let olaCalls = 0;
    const userId = await resolveSeatCupraUserId({
      idToken: "not-a-jwt",
      identityUserInfo: async () => ({ sub: "identity-user" }),
      olaUsers: async () => { olaCalls++; return { userId: "ola-user" }; },
    });
    expect(userId).to.equal("identity-user");
    expect(olaCalls).to.equal(0);
  });

  it("falls back to OLA /v1/users", async () => {
    const userId = await resolveSeatCupraUserId({
      identityUserInfo: async () => { throw new Error("userinfo unavailable"); },
      olaUsers: async () => ({ userId: "ola-user" }),
    });
    expect(userId).to.equal("ola-user");
  });

  it("throws one clear error after all user id sources fail", async () => {
    await expect(resolveSeatCupraUserId({
      idToken: "invalid",
      identityUserInfo: async () => { throw new Error("userinfo unavailable"); },
      olaUsers: async () => ({}),
    })).to.be.rejectedWith("SEAT/CUPRA user id could not be resolved");
  });

  it("prevents a garage request when seatcupraUser is undefined", () => {
    let requestCalled = false;
    expect(() => {
      const url = getSeatCupraGarageUrl(undefined);
      requestCalled = true;
      return url;
    }).to.throw("SEAT/CUPRA user id could not be resolved");
    expect(requestCalled).to.equal(false);
  });
});

describe("SEAT/CUPRA OLA headers", () => {
  for (const [type, brand] of [["seatcupra", "cupra"], ["seat", "seat"]]) {
    it(`builds required ${brand} headers`, () => {
      const headers = getSeatCupraOlaHeaders(type, "user-id", "access-token");
      expect(headers["app-brand"]).to.equal(brand);
      expect(headers["app-market"]).to.equal("android");
      expect(headers.origin).to.equal("app");
      expect(headers.Authorization).to.equal("Bearer access-token");
    });
  }
});

describe("secret redaction", () => {
  it("removes bearer tokens, JWTs, and OAuth token fields", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature";
    const redacted = redactSecrets(
      `Authorization: Bearer bearer-secret access_token=access-secret refresh_token=refresh-secret id_token=${jwt}`,
    );
    expect(redacted).not.to.include("bearer-secret");
    expect(redacted).not.to.include("access-secret");
    expect(redacted).not.to.include("refresh-secret");
    expect(redacted).not.to.include(jwt);
    expect(redacted).to.include("Bearer [REDACTED]");
  });
});
