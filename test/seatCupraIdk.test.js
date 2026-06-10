// @ts-nocheck
"use strict";

const { expect } = require("chai");
const {
  IDK_AUTHORIZE_URL,
  IDENTITY_TOKEN_URL,
  OLA_TOKEN_URL,
  BROWSER_USER_AGENT,
  SeatCupraIdkAuth,
  createSeatCupraPkce,
  buildSeatCupraAuthorizeUrl,
  buildSeatCupraTokenBody,
  getSeatCupraAuthStrategy,
  getSeatCupraMissingDeviceRecoveryStrategy,
  decodeJwtMetadataSafe,
  decodeJwtMetadata,
  upgradeSeatCupraClassicTokens,
} = require("../lib/seatCupraIdk");
const { getSeatCupraBrandConfig, getSeatCupraOlaHeaders } = require("../lib/seatCupra");

function encodeJwt(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `header.${encoded}.signature`;
}

function createRequest(handler) {
  const calls = [];
  const request = (options, callback) => {
    calls.push(options);
    const result = handler(options, calls.length - 1) || {};
    callback(null, {
      statusCode: result.status || 200,
      headers: result.headers || {},
      request: { uri: { href: result.url || options.url } },
    }, result.body || "");
  };
  request.jar = () => ({});
  request.calls = calls;
  return request;
}

function createAuth(type, request, logger = {}) {
  return new SeatCupraIdkAuth({
    brand: getSeatCupraBrandConfig(type),
    username: "user@example.test",
    password: "password-secret",
    request,
    logger,
  });
}

describe("SEAT/CUPRA classic IDK PKCE", () => {
  it("uses classic_idk by default and Device Grant only when explicitly selected", () => {
    expect(getSeatCupraAuthStrategy()).to.equal("classic_idk");
    expect(getSeatCupraAuthStrategy("unknown")).to.equal("classic_idk");
    expect(getSeatCupraAuthStrategy("classic_idk")).to.equal("classic_idk");
    expect(getSeatCupraAuthStrategy("device_grant")).to.equal("device_grant");
  });

  it("builds the classic PKCE authorize URL", () => {
    const brand = getSeatCupraBrandConfig("seatcupra");
    const pkce = createSeatCupraPkce();
    const url = new URL(buildSeatCupraAuthorizeUrl(brand, pkce));
    expect(url.origin + url.pathname).to.equal(IDK_AUTHORIZE_URL);
    expect(url.searchParams.get("client_id")).to.equal(brand.clientId);
    expect(url.searchParams.get("redirect_uri")).to.equal("cupra://oauth-callback");
    expect(url.searchParams.get("response_type")).to.equal("code");
    expect(url.searchParams.get("scope")).to.equal(brand.scope);
    expect(url.searchParams.get("code_challenge_method")).to.equal("S256");
    expect(url.searchParams.get("code_challenge")).to.equal(pkce.codeChallenge);
    expect(url.searchParams.get("prompt")).to.equal("login");
  });

  it("splits CUPRA and SEAT exchange and refresh endpoints", () => {
    const cupra = getSeatCupraBrandConfig("seatcupra");
    const seat = getSeatCupraBrandConfig("seat");
    expect(cupra.exchangeTokenUrl).to.equal(IDENTITY_TOKEN_URL);
    expect(cupra.refreshTokenUrl).to.equal(OLA_TOKEN_URL);
    expect(seat.exchangeTokenUrl).to.equal(OLA_TOKEN_URL);
    expect(seat.refreshTokenUrl).to.equal(OLA_TOKEN_URL);
  });

  it("builds authorization-code and refresh token bodies", () => {
    const brand = getSeatCupraBrandConfig("seatcupra");
    const exchange = new URLSearchParams(buildSeatCupraTokenBody(brand, {
      grantType: "authorization_code",
      code: "auth-code",
      codeVerifier: "verifier",
    }));
    expect(exchange.get("grant_type")).to.equal("authorization_code");
    expect(exchange.get("code_verifier")).to.equal("verifier");
    expect(exchange.get("redirect_uri")).to.equal("cupra://oauth-callback");
    expect(exchange.get("client_secret")).to.equal(brand.clientSecret);

    const refresh = new URLSearchParams(buildSeatCupraTokenBody(brand, {
      grantType: "refresh_token",
      refreshToken: "refresh-token",
    }));
    expect(refresh.get("grant_type")).to.equal("refresh_token");
    expect(refresh.get("refresh_token")).to.equal("refresh-token");
    expect(refresh.has("code_verifier")).to.equal(false);
  });

  it("uses the correct exchange and refresh endpoint for each brand", async () => {
    for (const type of ["seatcupra", "seat"]) {
      const request = createRequest(() => ({
        body: JSON.stringify({ access_token: "access", refresh_token: "refresh", expires_in: 3600 }),
      }));
      const auth = createAuth(type, request);
      const brand = getSeatCupraBrandConfig(type);
      await auth.exchangeCode("code-secret", "verifier-secret");
      await auth.refresh("refresh-secret");
      expect(request.calls[0].url).to.equal(brand.exchangeTokenUrl);
      expect(request.calls[1].url).to.equal(brand.refreshTokenUrl);
    }
  });

  for (const rejectedStatus of [401, 403]) {
    it(`retries an initial authorize ${rejectedStatus} once with a browser User-Agent`, async () => {
      let authorizeCalls = 0;
      const request = createRequest((options) => {
        const url = new URL(options.url);
        if (url.pathname === "/oidc/v1/authorize") {
          authorizeCalls++;
          if (authorizeCalls === 1) return { status: rejectedStatus };
          return { status: 302, headers: { location: "/u/login?state=auth0-state" } };
        }
        return {
          body: '<form><input type="hidden" name="state" value="auth0-state"></form>',
        };
      });
      const auth = createAuth("seatcupra", request);
      auth.jar = request.jar();
      const authorizeUrl = buildSeatCupraAuthorizeUrl(auth.brand, createSeatCupraPkce());
      const landing = await auth.getAuthorizeLanding(authorizeUrl);
      expect(landing.url).to.include("/u/login");
      expect(request.calls[0].url).to.equal(request.calls[1].url);
      expect(request.calls[0].headers["User-Agent"]).to.equal(auth.brand.oauthUserAgent);
      expect(request.calls[1].headers["User-Agent"]).to.equal(BROWSER_USER_AGENT);
    });
  }

  it("completes Auth0 form_post login with compatible headers", async () => {
    let oauthState;
    const request = createRequest((options) => {
      const url = new URL(options.url);
      if (url.pathname === "/oidc/v1/authorize") {
        oauthState = url.searchParams.get("state");
        return { status: 302, headers: { location: "/u/login?state=auth0-state" } };
      }
      if (url.pathname === "/u/login" && options.method === "GET") {
        return { body: '<form><input name="state" value="auth0-state"></form>' };
      }
      if (url.pathname === "/u/login" && options.method === "POST") {
        return { status: 302, headers: { location: "/authorize/resume" } };
      }
      if (url.pathname === "/authorize/resume") {
        return { body: '<form action="/login/callback"><input name="state" value="callback-state"></form>' };
      }
      if (url.pathname === "/login/callback") {
        return { status: 302, headers: { location: `cupra://oauth-callback?code=code-secret&state=${oauthState}` } };
      }
      if (options.url === IDENTITY_TOKEN_URL) {
        return { body: JSON.stringify({ access_token: "access-secret", refresh_token: "refresh-secret", expires_in: 3600 }) };
      }
      throw new Error(`Unexpected request ${options.method || "GET"} ${url.pathname}`);
    });
    const auth = createAuth("seatcupra", request);
    const tokens = await auth.authenticate();
    expect(tokens.access_token).to.equal("access-secret");
    const loginPost = request.calls.find((call) => new URL(call.url).pathname === "/u/login" && call.method === "POST");
    expect(loginPost.headers.Accept).to.equal("text/html,application/xhtml+xml,*/*");
    expect(loginPost.headers.Origin).to.equal("https://identity.vwgroup.io");
    expect(loginPost.headers.Referer).to.include("/u/login");
    expect(loginPost.headers["Content-Type"]).to.equal("application/x-www-form-urlencoded");
  });

  it("falls back to the legacy signin-service flow when /u/login is absent", async () => {
    let oauthState;
    const request = createRequest((options) => {
      const url = new URL(options.url);
      if (url.pathname === "/oidc/v1/authorize") {
        oauthState = url.searchParams.get("state");
        return { status: 302, headers: { location: "/signin-service/v1/client/login" } };
      }
      if (url.pathname.endsWith("/login") && options.method === "GET") {
        return {
          body: '<form action="/signin-service/v1/client/login/identifier">' +
            '<input name="_csrf" value="csrf-secret"><input name="relayState" value="relay-secret"></form>',
        };
      }
      if (url.pathname.endsWith("/identifier")) {
        return { body: '<script>window.model={"hmac":"abcdef012345"}</script>' };
      }
      if (url.pathname.endsWith("/authenticate")) {
        return { status: 302, headers: { location: `cupra://oauth-callback?code=legacy-code&state=${oauthState}` } };
      }
      if (options.url === IDENTITY_TOKEN_URL) {
        return { body: JSON.stringify({ access_token: "legacy-access", refresh_token: "legacy-refresh" }) };
      }
      throw new Error(`Unexpected legacy request ${options.method || "GET"} ${url.pathname}`);
    });
    const auth = createAuth("seatcupra", request);
    const tokens = await auth.authenticate();
    expect(tokens.access_token).to.equal("legacy-access");
    expect(request.calls.some((call) => new URL(call.url).pathname.endsWith("/identifier"))).to.equal(true);
    expect(request.calls.some((call) => new URL(call.url).pathname.endsWith("/authenticate"))).to.equal(true);
  });

  it("raises clear errors for MFA and terms URLs", async () => {
    const request = createRequest(() => { throw new Error("challenge URL must not be requested"); });
    const auth = createAuth("seatcupra", request);
    auth.jar = request.jar();
    for (const [url, message] of [
      ["https://identity.vwgroup.io/u/mfa?state=secret", "additional verification"],
      ["https://identity.vwgroup.io/signin-service/v1/terms-and-conditions?state=secret", "terms and conditions"],
    ]) {
      let error;
      try { await auth.followBrowser(url); } catch (caught) { error = caught; }
      expect(error.message).to.include(message);
      expect(error.message).not.to.include("secret");
    }
  });

  it("skips marketing consent when an OIDC callback is present", async () => {
    const request = createRequest(() => ({
      status: 302,
      headers: { location: "cupra://oauth-callback?code=consent-code" },
    }));
    const auth = createAuth("seatcupra", request);
    auth.jar = request.jar();
    const callback = encodeURIComponent("https://identity.vwgroup.io/authorize/resume");
    const result = await auth.followBrowser(`https://cupraid.vwgroup.io/consent/marketing?callback=${callback}`);
    expect(result.url).to.equal("cupra://oauth-callback?code=consent-code");
    expect(request.calls).to.have.length(1);
  });

  it("marks invalid_grant as reauthentication and 5xx as transient", async () => {
    const invalidRequest = createRequest(() => ({ status: 400, body: JSON.stringify({ error: "invalid_grant" }) }));
    let invalidGrantError;
    try { await createAuth("seatcupra", invalidRequest).refresh("refresh-token"); } catch (error) { invalidGrantError = error; }
    expect(invalidGrantError.invalidGrant).to.equal(true);
    expect(invalidGrantError.transient).to.equal(false);

    const transientRequest = createRequest(() => ({ status: 503, body: "{}" }));
    let transientError;
    try { await createAuth("seatcupra", transientRequest).refresh("refresh-token"); } catch (error) { transientError = error; }
    expect(transientError.transient).to.equal(true);
  });

  it("upgrades identity tokens via OLA refresh and preserves the original id_token", async () => {
    const identityIdToken = encodeJwt({ aud: "identity-client", exp: 1900000000 });
    let refreshCalls = 0;
    const result = await upgradeSeatCupraClassicTokens({
      access_token: "identity-access",
      refresh_token: "identity-refresh",
      id_token: identityIdToken,
      expires_in: 3600,
    }, async (refreshToken) => {
      refreshCalls++;
      expect(refreshToken).to.equal("identity-refresh");
      return { access_token: "ola-access", refresh_token: "ola-refresh", expires_in: 3600 };
    });
    expect(refreshCalls).to.equal(1);
    expect(result.origin).to.equal("classic_idk_ola_refresh");
    expect(result.outcome).to.equal("upgraded");
    expect(result.tokens.access_token).to.equal("ola-access");
    expect(result.tokens.refresh_token).to.equal("ola-refresh");
    expect(result.tokens.id_token).to.equal(identityIdToken);
  });

  it("keeps identity tokens when the immediate OLA refresh is transient or rejected", async () => {
    const identityTokens = {
      access_token: "identity-access",
      refresh_token: "identity-refresh",
      id_token: "identity-id",
    };
    for (const [error, outcome] of [
      [Object.assign(new Error("temporary"), { transient: true }), "transient"],
      [Object.assign(new Error("invalid grant"), { invalidGrant: true }), "rejected"],
    ]) {
      let calls = 0;
      const result = await upgradeSeatCupraClassicTokens(identityTokens, async () => {
        calls++;
        throw error;
      });
      expect(calls).to.equal(1);
      expect(result.outcome).to.equal(outcome);
      expect(result.origin).to.equal("classic_idk_identity_exchange");
      expect(result.tokens).to.deep.equal(identityTokens);
    }
  });

  it("reports access_token and id_token metadata separately without subject or raw tokens", () => {
    const accessToken = encodeJwt({
      sub: "private-user",
      aud: "ola-api",
      exp: 1900000000,
      scope: "openid profile",
    });
    const idToken = encodeJwt({ sub: "private-user", aud: "cupra-client", exp: 1900000100 });
    const accessMetadata = decodeJwtMetadataSafe(accessToken, "access_token", "classic_idk");
    const idMetadata = decodeJwtMetadataSafe(idToken, "id_token", "classic_idk");
    expect(accessMetadata).to.include({
      label: "access_token",
      strategy: "classic_idk",
      exists: true,
      len: accessToken.length,
      aud: "ola-api",
      scope: "openid profile",
    });
    expect(idMetadata).to.include({
      label: "id_token",
      strategy: "classic_idk",
      exists: true,
      len: idToken.length,
      aud: "cupra-client",
    });
    const output = JSON.stringify([accessMetadata, idMetadata]);
    expect(output).not.to.include("private-user");
    expect(output).not.to.include(accessToken);
    expect(output).not.to.include(idToken);
    expect(accessMetadata).not.to.have.property("sub");
    expect(idMetadata).not.to.have.property("sub");
  });

  it("wires the immediate OLA upgrade into fresh classic login", () => {
    const source = require("fs").readFileSync(require("path").join(__dirname, "..", "main.js"), "utf8");
    const start = source.indexOf("  async loginSeatCupraClassicIdk(");
    const end = source.indexOf("  async loginSeatCupra(", start);
    const loginMethod = source.slice(start, end);
    expect(loginMethod).to.include("upgradeSeatCupraClassicTokens(tokens");
    expect(loginMethod).to.include("auth.refresh(refreshToken)");
    expect(loginMethod).to.include("classic_idk_ola_refresh");
  });

  it("switches Device Grant missing-device-token recovery to classic IDK", () => {
    expect(getSeatCupraMissingDeviceRecoveryStrategy("device_grant")).to.equal("classic_idk");
    expect(getSeatCupraMissingDeviceRecoveryStrategy("classic_idk")).to.equal("classic_idk");
  });

  it("logs only safe endpoint and JWT metadata diagnostics", async () => {
    const messages = [];
    const logger = { info: (message) => messages.push(message), debug: (message) => messages.push(message) };
    const request = createRequest(() => ({
      body: JSON.stringify({ access_token: "access-secret", refresh_token: "refresh-secret" }),
    }));
    const auth = createAuth("seatcupra", request, logger);
    await auth.exchangeCode("auth-code-secret", "verifier-secret");
    await auth.refresh("refresh-secret");
    const token = encodeJwt({ sub: "private-user", exp: 1900000000, aud: "cupra", iss: "issuer" });
    messages.push(JSON.stringify(decodeJwtMetadata(token, "classic_idk")));
    const output = messages.join("\n");
    expect(output).to.include("token exchange endpoint: identity");
    expect(output).to.include("refresh endpoint: ola");
    for (const secret of [
      "access-secret", "refresh-secret", "auth-code-secret", "verifier-secret", token, "private-user",
    ]) expect(output).not.to.include(secret);
  });

  it("keeps the aligned CUPRA OLA read headers unchanged", () => {
    const headers = getSeatCupraOlaHeaders("seatcupra", "user-id", "access-token", "primary", "VIN");
    expect(headers["User-Agent"]).to.equal(
      "OLACupra/2.15.0 (Android 12; sdk_gphone64_x86_64; Google) Mobile",
    );
    expect(headers["app-version"]).to.equal("2.15.0");
    expect(headers["app-brand"]).to.equal("cupra");
    expect(headers).not.to.have.property("User-ID");
    expect(headers).not.to.have.property("VIN");
    expect(headers).not.to.have.property("Accept-Language");
  });
});
