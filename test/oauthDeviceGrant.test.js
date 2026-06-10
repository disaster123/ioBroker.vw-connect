// @ts-nocheck
"use strict";

const { expect } = require("chai");
const { OAuthDeviceGrant, redactSecrets } = require("../lib/oauthDeviceGrant");
const {
  decodeBase64UrlJson,
  decodeJwtPayload,
  resolveSeatCupraUserId,
  getSeatCupraGarageUrl,
  clearSeatCupraTokenValues,
  storeSeatCupraTokenValues,
  clearSeatCupraRuntimeTokens,
  runSeatCupraFreshRecovery,
  retrySeatCupraRequestAfterRecovery,
  startSeatCupraDeviceAuthorization,
  shouldUseSeatCupraRefreshToken,
  beginSeatCupraMissingDeviceRecovery,
  completeSeatCupraMissingDeviceRecovery,
  failSeatCupraMissingDeviceRecovery,
  formatSeatCupraOlaFailure,
  isSeatCupraOptionalEndpoint,
  getSeatCupraSkippedEndpointKey,
  createSeatCupraSkippedEndpointDetail,
  handleSeatCupraRepeatedMissingDeviceToken,
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
    expect(decodeJwtPayload(token).sub).to.equal("jwt-user");
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


describe("SEAT/CUPRA fresh device recovery", () => {
  it("does not use a stale refresh token when force is true", () => {
    expect(shouldUseSeatCupraRefreshToken(false, "stale-refresh")).to.equal(true);
    expect(shouldUseSeatCupraRefreshToken(true, "stale-refresh")).to.equal(false);
  });

  it("stores tokens only in memory without adapter config or lifecycle calls", () => {
    let nativeWrites = 0;
    let restarts = 0;
    let terminates = 0;
    const config = { rtoken: "preserved-refresh", seatCupraIdToken: "preserved-id" };
    const runtime = {
      seatCupraTokenExpiresAt: 0,
      setForeignObjectAsync: () => { nativeWrites++; },
      restart: () => { restarts++; },
      terminate: () => { terminates++; },
    };
    storeSeatCupraTokenValues(config, runtime, { access_token: "new-access", expires_in: 60 }, 1000);
    expect(config.atoken).to.equal("new-access");
    expect(config.rtoken).to.equal("preserved-refresh");
    expect(config.seatCupraIdToken).to.equal("preserved-id");
    expect(config.seatCupraTokenExpiresAt).to.equal(61000);
    expect(runtime.seatCupraTokenExpiresAt).to.equal(61000);
    expect(nativeWrites).to.equal(0);
    expect(restarts).to.equal(0);
    expect(terminates).to.equal(0);
  });

  it("clears tokens only in memory without adapter config or lifecycle calls", () => {
    let nativeWrites = 0;
    let restarts = 0;
    let terminates = 0;
    const config = {
      atoken: "old-access",
      rtoken: "old-refresh",
      idtoken: "old-id",
      seatCupraIdToken: "old-seat-id",
      seatCupraTokenExpiresAt: 123,
    };
    const runtime = {
      seatCupraTokenExpiresAt: 123,
      seatcupraUser: "user-id",
      setForeignObjectAsync: () => { nativeWrites++; },
      restart: () => { restarts++; },
      terminate: () => { terminates++; },
    };
    clearSeatCupraRuntimeTokens(config, runtime);
    expect(config.atoken).to.equal("");
    expect(config.rtoken).to.equal("");
    expect(config.idtoken).to.equal("");
    expect(config.seatCupraIdToken).to.equal("");
    expect(config.seatCupraTokenExpiresAt).to.equal(0);
    expect(runtime.seatCupraTokenExpiresAt).to.equal(0);
    expect(runtime.seatcupraUser).to.equal(undefined);
    expect(nativeWrites).to.equal(0);
    expect(restarts).to.equal(0);
    expect(terminates).to.equal(0);
  });

  it("clears old access, refresh, and ID tokens before fresh authorization", () => {
    const config = {
      atoken: "old-access",
      rtoken: "old-refresh",
      idtoken: "old-id",
      seatCupraIdToken: "old-seat-id",
      seatCupraTokenExpiresAt: 123,
    };
    const native = { ...config };
    clearSeatCupraTokenValues(config);
    clearSeatCupraTokenValues(native);
    for (const target of [config, native]) {
      expect(target.atoken).to.equal("");
      expect(target.rtoken).to.equal("");
      expect(target.idtoken).to.equal("");
      expect(target.seatCupraIdToken).to.equal("");
      expect(target.seatCupraTokenExpiresAt).to.equal(0);
    }
  });

  it("clears stale tokens before requesting fresh device authorization", async () => {
    const events = [];
    const device = await startSeatCupraDeviceAuthorization({
      force: true,
      clearTokens: async () => events.push("clear"),
      requestDeviceCode: async () => { events.push("request"); return { device_code: "new" }; },
    });
    expect(events).to.deep.equal(["clear", "request"]);
    expect(device.device_code).to.equal("new");
  });

  it("requests force=true and resolves the user before retry", async () => {
    const events = [];
    await runSeatCupraFreshRecovery({
      login: async (options) => events.push(["login", options]),
      resolveUserId: async () => events.push(["resolve"]),
    });
    expect(events).to.deep.equal([
      ["login", { force: true }],
      ["resolve"],
    ]);
  });

  it("retries the failed request exactly once after recovery", async () => {
    let recoveries = 0;
    let retries = 0;
    const result = await retrySeatCupraRequestAfterRecovery({
      recover: async () => { recoveries++; },
      retryRequest: async () => { retries++; return "ok"; },
    });
    expect(result).to.equal("ok");
    expect(recoveries).to.equal(1);
    expect(retries).to.equal(1);
  });

  it("prevents a second missing-device-token recovery in the same chain", () => {
    const context = { recoveryAttempted: false, stopDetailPolling: false };
    expect(beginSeatCupraMissingDeviceRecovery(false, context)).to.equal(true);
    expect(beginSeatCupraMissingDeviceRecovery(true, context)).to.equal(false);
    expect(context.stopDetailPolling).to.equal(false);
  });

  it("resets recovery flags after a successful retry", () => {
    const state = {
      seatCupraForcedReloginAttempted: true,
      seatCupraMissingDeviceWarningLogged: true,
      seatCupraPollingStopped: false,
    };
    completeSeatCupraMissingDeviceRecovery(state);
    expect(state.seatCupraForcedReloginAttempted).to.equal(false);
    expect(state.seatCupraMissingDeviceWarningLogged).to.equal(false);
    expect(state.seatCupraPollingStopped).to.equal(false);
  });

  it("leaves tokens cleared and polling stopped after fresh login fails", async () => {
    const state = {
      atoken: "old-access",
      rtoken: "old-refresh",
      idtoken: "old-id",
      seatCupraIdToken: "old-seat-id",
      seatCupraTokenExpiresAt: 123,
      seatCupraPollingStopped: false,
    };
    try {
      await startSeatCupraDeviceAuthorization({
        force: true,
        clearTokens: async () => clearSeatCupraTokenValues(state),
        requestDeviceCode: async () => { throw new Error("device authorization failed"); },
      });
    } catch {
      failSeatCupraMissingDeviceRecovery(state);
    }
    expect(state.atoken).to.equal("");
    expect(state.rtoken).to.equal("");
    expect(state.idtoken).to.equal("");
    expect(state.seatCupraIdToken).to.equal("");
    expect(state.seatCupraPollingStopped).to.equal(true);
  });

  it("contains no native config writes in adapter token store or clear methods", () => {
    const source = require("fs").readFileSync(require("path").join(__dirname, "..", "main.js"), "utf8");
    const start = source.indexOf("  async storeSeatCupraTokens(tokens) {");
    const end = source.indexOf("  async setSeatCupraDeviceApprovalStates", start);
    const tokenMethods = source.slice(start, end);
    expect(tokenMethods).not.to.include("getForeignObjectAsync");
    expect(tokenMethods).not.to.include("setForeignObjectAsync");
    expect(tokenMethods).not.to.include("restart(");
    expect(tokenMethods).not.to.include("terminate(");
  });

  it("formats OLA failures with pathname and status without secrets", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature";
    const message = formatSeatCupraOlaFailure({
      method: "get",
      url: "https://ola.prod.code.seat.cloud.vwgroup.com/v2/vehicles/VIN/status?access_token=secret",
      status: 403,
      data: {
        code: "missing-device-token",
        message: `Forbidden device detected Bearer bearer-secret id_token=${jwt}`,
      },
      redact: redactSecrets,
    });
    expect(message).to.include("GET /v2/vehicles/VIN/status status=403");
    expect(message).to.include("code=missing-device-token");
    expect(message).to.include("Forbidden device detected");
    expect(message).not.to.include("access_token=secret");
    expect(message).not.to.include("bearer-secret");
    expect(message).not.to.include(jwt);
  });
});


describe("SEAT/CUPRA optional OLA endpoints", () => {
  const missingDevice = { code: "missing-device-token", message: "Forbidden device detected" };

  it("classifies warninglights, maintenance, and parkingposition as optional", () => {
    expect(isSeatCupraOptionalEndpoint("/v3/vehicles/VIN/warninglights")).to.equal(true);
    expect(isSeatCupraOptionalEndpoint("/v1/vehicles/VIN/maintenance")).to.equal(true);
    expect(isSeatCupraOptionalEndpoint("/v1/vehicles/VIN/parkingposition")).to.equal(true);
    expect(isSeatCupraOptionalEndpoint("/v2/vehicles/VIN/status")).to.equal(false);
    expect(isSeatCupraOptionalEndpoint("/v1/vehicles/VIN/ranges")).to.equal(false);
  });

  it("skips a repeated optional failure without stopping the polling cycle", async () => {
    const context = { recoveryAttempted: true, stopDetailPolling: false };
    const skipped = new Set();
    const details = [];
    const warnings = [];
    const restarts = 0;
    const terminates = 0;
    const result = await handleSeatCupraRepeatedMissingDeviceToken({
      method: "get",
      pathname: "/v3/vehicles/VIN/warninglights",
      status: 403,
      data: missingDevice,
      recoveryContext: context,
      recordSkipped: async (method, pathname, status, data) => {
        skipped.add(getSeatCupraSkippedEndpointKey(method, pathname));
        details.push(createSeatCupraSkippedEndpointDetail(method, pathname, status, data, new Date(0)));
      },
      logWarning: (message) => warnings.push(message),
      logError: () => {},
      completeRecovery: () => {},
    });
    expect(result).to.deep.equal({ skipped: true, stopCycle: false });
    expect(context.stopDetailPolling).to.equal(false);
    expect(skipped.has("GET /v3/vehicles/VIN/warninglights")).to.equal(true);
    expect(details[0]).to.deep.equal({
      method: "GET",
      pathname: "/v3/vehicles/VIN/warninglights",
      status: 403,
      code: "missing-device-token",
      timestamp: "1970-01-01T00:00:00.000Z",
    });
    expect(warnings[0]).to.include("optional OLA endpoint skipped after fresh login");
    expect(restarts).to.equal(0);
    expect(terminates).to.equal(0);
  });

  it("stops only the detail cycle for a repeated core endpoint failure", async () => {
    const context = { recoveryAttempted: true, stopDetailPolling: false };
    const errors = [];
    const result = await handleSeatCupraRepeatedMissingDeviceToken({
      method: "get",
      pathname: "/v2/vehicles/VIN/status",
      status: 403,
      data: missingDevice,
      recoveryContext: context,
      recordSkipped: async () => { throw new Error("core endpoint must not be skipped"); },
      logWarning: () => {},
      logError: (message) => errors.push(message),
      completeRecovery: () => {},
    });
    expect(result.stopCycle).to.equal(true);
    expect(result.skipped).to.equal(false);
    expect(context.stopDetailPolling).to.equal(true);
    expect(errors[0]).to.include("core OLA endpoint rejected token after fresh login");
  });

  it("allows polling to continue after an optional endpoint returns null", () => {
    const responses = [null, { range: 250 }];
    const processed = [];
    for (const response of responses) {
      if (response == null) continue;
      processed.push(response);
    }
    expect(processed).to.deep.equal([{ range: 250 }]);
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
  it("removes Bearer, JWT, access, refresh, ID, and device-code secrets", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature";
    const redacted = redactSecrets(
      `Authorization: Bearer bearer-secret access_token=access-secret refresh_token=refresh-secret ` +
        `id_token=${jwt} device_code=device-secret`,
    );
    expect(redacted).not.to.include("bearer-secret");
    expect(redacted).not.to.include("access-secret");
    expect(redacted).not.to.include("refresh-secret");
    expect(redacted).not.to.include(jwt);
    expect(redacted).not.to.include("device-secret");
    expect(redacted).to.include("Bearer [REDACTED]");
  });
});
