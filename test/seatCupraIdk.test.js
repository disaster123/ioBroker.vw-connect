// @ts-nocheck
"use strict";

const { expect } = require("chai");
const {
  IDK_TOKEN_URL,
  SeatCupraIdkAuth,
  createSeatCupraPkce,
  buildSeatCupraAuthorizeUrl,
  buildSeatCupraTokenBody,
  getSeatCupraAuthStrategy,
  getSeatCupraMissingDeviceRecoveryStrategy,
  decodeJwtMetadata,
} = require("../lib/seatCupraIdk");
const { getSeatCupraBrandConfig, getSeatCupraOlaHeaders } = require("../lib/seatCupra");

function encodeJwt(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `header.${encoded}.signature`;
}

describe("SEAT/CUPRA classic IDK PKCE", () => {
  it("uses classic_idk by default and Device Grant only when explicitly selected", () => {
    expect(getSeatCupraAuthStrategy()).to.equal("classic_idk");
    expect(getSeatCupraAuthStrategy("classic_idk")).to.equal("classic_idk");
    expect(getSeatCupraAuthStrategy("device_grant")).to.equal("device_grant");
  });

  it("builds the classic PKCE authorize URL", () => {
    const brand = getSeatCupraBrandConfig("seatcupra");
    const pkce = createSeatCupraPkce();
    const url = new URL(buildSeatCupraAuthorizeUrl(brand, pkce));
    expect(url.origin + url.pathname).to.equal("https://identity.vwgroup.io/oidc/v1/authorize");
    expect(url.searchParams.get("client_id")).to.equal(brand.clientId);
    expect(url.searchParams.get("redirect_uri")).to.equal("cupra://oauth-callback");
    expect(url.searchParams.get("response_type")).to.equal("code");
    expect(url.searchParams.get("scope")).to.equal(brand.scope);
    expect(url.searchParams.get("code_challenge_method")).to.equal("S256");
    expect(url.searchParams.get("code_challenge")).to.equal(pkce.codeChallenge);
    expect(url.searchParams.get("prompt")).to.equal("login");
  });


  it("uses the reference token endpoint for each brand", () => {
    expect(getSeatCupraBrandConfig("seatcupra").idkTokenUrl).to.equal(IDK_TOKEN_URL);
    expect(getSeatCupraBrandConfig("seat").idkTokenUrl).to.equal(
      "https://ola.prod.code.seat.cloud.vwgroup.com/authorization/api/v1/token",
    );
  });

  it("builds authorization-code and refresh token bodies", () => {
    const brand = getSeatCupraBrandConfig("seatcupra");
    const exchange = new URLSearchParams(buildSeatCupraTokenBody(brand, {
      grantType: "authorization_code",
      code: "auth-code",
      codeVerifier: "verifier",
    }));
    expect(exchange.get("grant_type")).to.equal("authorization_code");
    expect(exchange.get("code")).to.equal("auth-code");
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

  it("completes Auth0 form_post login and exchanges the code at the IDK token endpoint", async () => {
    const brand = getSeatCupraBrandConfig("seatcupra");
    const calls = [];
    let oauthState;
    const request = (options, callback) => {
      calls.push(options);
      const url = new URL(options.url);
      let statusCode = 200;
      const headers = {};
      let body = "";
      if (url.pathname === "/oidc/v1/authorize") {
        oauthState = url.searchParams.get("state");
        statusCode = 302;
        headers.location = "/u/login?state=auth0-state";
      } else if (url.pathname === "/u/login" && options.method === "GET") {
        body = '<form><input type="hidden" name="state" value="auth0-state"></form>';
      } else if (url.pathname === "/u/login" && options.method === "POST") {
        statusCode = 302;
        headers.location = "/authorize/resume";
      } else if (url.pathname === "/authorize/resume") {
        body = '<form action="/login/callback"><input name="state" value="callback-state"></form>';
      } else if (url.pathname === "/login/callback") {
        statusCode = 302;
        headers.location = `cupra://oauth-callback?code=authorization-code&state=${oauthState}`;
      } else if (options.url === brand.idkTokenUrl) {
        body = JSON.stringify({
          access_token: "access-token",
          refresh_token: "refresh-token",
          id_token: encodeJwt({ sub: "user-id" }),
          expires_in: 3600,
        });
      } else {
        throw new Error(`Unexpected request ${options.method || "GET"} ${options.url}`);
      }
      callback(null, { statusCode, headers }, body);
    };
    request.jar = () => ({});

    const auth = new SeatCupraIdkAuth({
      brand,
      username: "user@example.test",
      password: "password",
      request,
    });
    const tokens = await auth.authenticate();
    expect(tokens.access_token).to.equal("access-token");
    const tokenCall = calls.find((call) => call.url === IDK_TOKEN_URL);
    const tokenBody = new URLSearchParams(tokenCall.body);
    expect(tokenBody.get("grant_type")).to.equal("authorization_code");
    expect(tokenBody.get("code")).to.equal("authorization-code");
    expect(tokenBody.get("code_verifier")).to.be.a("string").and.not.empty;
  });

  it("marks invalid_grant as reauthentication and 5xx as transient", async () => {
    const brand = getSeatCupraBrandConfig("seatcupra");
    const makeRequest = (status, payload) => {
      const request = (options, callback) => callback(
        null,
        { statusCode: status, headers: {} },
        JSON.stringify(payload),
      );
      request.jar = () => ({});
      return request;
    };
    const invalidGrantAuth = new SeatCupraIdkAuth({
      brand,
      username: "user",
      password: "password",
      request: makeRequest(400, { error: "invalid_grant" }),
    });
    let invalidGrantError;
    try {
      await invalidGrantAuth.refresh("refresh-token");
    } catch (error) {
      invalidGrantError = error;
    }
    expect(invalidGrantError.invalidGrant).to.equal(true);
    expect(invalidGrantError.transient).to.equal(false);

    const transientAuth = new SeatCupraIdkAuth({
      brand,
      username: "user",
      password: "password",
      request: makeRequest(503, {}),
    });
    let transientError;
    try {
      await transientAuth.refresh("refresh-token");
    } catch (error) {
      transientError = error;
    }
    expect(transientError.transient).to.equal(true);
    expect(transientError.invalidGrant).to.equal(false);
  });

  it("switches Device Grant missing-device-token recovery to classic IDK", () => {
    expect(getSeatCupraMissingDeviceRecoveryStrategy("device_grant")).to.equal("classic_idk");
    expect(getSeatCupraMissingDeviceRecoveryStrategy("classic_idk")).to.equal("classic_idk");
  });

  it("exposes only sanitized JWT metadata", () => {
    const token = encodeJwt({
      sub: "private-user-id",
      exp: 1900000000,
      aud: "cupra-api",
      azp: "cupra-client",
      iss: "https://identity.vwgroup.io/",
    });
    const metadata = decodeJwtMetadata(token, "classic_idk");
    expect(metadata).to.deep.equal({
      strategy: "classic_idk",
      exp: 1900000000,
      aud: "cupra-api",
      azp: "cupra-client",
      iss: "https://identity.vwgroup.io/",
    });
    expect(JSON.stringify(metadata)).not.to.include(token);
    expect(JSON.stringify(metadata)).not.to.include("private-user-id");
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
