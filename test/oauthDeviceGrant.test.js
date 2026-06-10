// @ts-nocheck
"use strict";

const { expect } = require("chai");
const { OAuthDeviceGrant, redactSecrets } = require("../lib/oauthDeviceGrant");
const { getSeatCupraOlaHeaders } = require("../lib/seatCupra");

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
  it("removes bearer tokens and JWTs", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature";
    const redacted = redactSecrets(`Authorization: Bearer ${jwt} access_token=${jwt}`);
    expect(redacted).not.to.include(jwt);
    expect(redacted).to.include("Bearer [REDACTED]");
  });
});
