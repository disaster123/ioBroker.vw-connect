// @ts-nocheck
"use strict";

const crypto = require("crypto");

const IDK_AUTHORIZE_URL = "https://identity.vwgroup.io/oidc/v1/authorize";
const IDK_TOKEN_URL = "https://identity.vwgroup.io/oidc/v1/token";
const TRANSIENT_TOKEN_STATUSES = new Set([500, 502, 503, 504]);

class SeatCupraIdkError extends Error {
  constructor(message, { status, transient = false, invalidGrant = false } = {}) {
    super(message);
    this.name = "SeatCupraIdkError";
    this.status = status;
    this.transient = transient;
    this.invalidGrant = invalidGrant;
  }
}

function base64Url(buffer) {
  return Buffer.from(buffer).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function createSeatCupraPkce() {
  const codeVerifier = base64Url(crypto.randomBytes(32));
  return {
    codeVerifier,
    codeChallenge: base64Url(crypto.createHash("sha256").update(codeVerifier).digest()),
    state: base64Url(crypto.randomBytes(16)),
    nonce: base64Url(crypto.randomBytes(16)),
  };
}

function buildSeatCupraAuthorizeUrl(brand, pkce) {
  const url = new URL(IDK_AUTHORIZE_URL);
  url.search = new URLSearchParams({
    client_id: brand.clientId,
    redirect_uri: brand.redirectUri,
    response_type: "code",
    scope: brand.scope,
    state: pkce.state,
    nonce: pkce.nonce,
    code_challenge: pkce.codeChallenge,
    code_challenge_method: "S256",
    prompt: "login",
  }).toString();
  return url.toString();
}

function buildSeatCupraTokenBody(brand, grant) {
  const body = new URLSearchParams({
    client_id: brand.clientId,
    grant_type: grant.grantType,
  });
  if (grant.grantType === "authorization_code") {
    body.set("redirect_uri", brand.redirectUri);
    body.set("code", grant.code);
    body.set("code_verifier", grant.codeVerifier);
  } else if (grant.grantType === "refresh_token") {
    body.set("refresh_token", grant.refreshToken);
  }
  if (brand.clientSecret) body.set("client_secret", brand.clientSecret);
  return body.toString();
}

function getSeatCupraAuthStrategy(configuredStrategy) {
  return configuredStrategy === "device_grant" ? "device_grant" : "classic_idk";
}

function getSeatCupraMissingDeviceRecoveryStrategy() {
  return "classic_idk";
}

function decodeJwtMetadata(token, strategy) {
  const metadata = { strategy };
  if (typeof token !== "string") return metadata;
  const part = token.split(".")[1];
  if (!part) return metadata;
  try {
    const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    const payload = JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
    for (const key of ["exp", "aud", "azp", "iss"]) {
      if (payload[key] !== undefined) metadata[key] = payload[key];
    }
  } catch {
    // Metadata is diagnostic only; malformed or opaque tokens are valid inputs.
  }
  return metadata;
}

function parseHtmlAttributes(tag) {
  const attributes = {};
  for (const match of tag.matchAll(/([\w:-]+)\s*=\s*(["'])(.*?)\2/gis)) {
    attributes[match[1].toLowerCase()] = match[3];
  }
  return attributes;
}

function parseHtmlForm(html) {
  const formTag = String(html || "").match(/<form\b[^>]*>/i);
  if (!formTag) return undefined;
  const formAttributes = parseHtmlAttributes(formTag[0]);
  const fields = {};
  for (const input of String(html).matchAll(/<input\b[^>]*>/gi)) {
    const attributes = parseHtmlAttributes(input[0]);
    if (attributes.name) fields[attributes.name] = attributes.value || "";
  }
  return { action: formAttributes.action || "", fields };
}

function extractSeatCupraAuthorizationCode(location, redirectUri, expectedState) {
  if (typeof location !== "string" || !location.startsWith(redirectUri.split("://")[0] + "://")) return undefined;
  const parsed = new URL(location);
  const sources = [parsed.searchParams, new URLSearchParams(parsed.pathname.replace(/^\/?\??/, "")), new URLSearchParams(parsed.hash.replace(/^#/, ""))];
  for (const params of sources) {
    const code = params.get("code");
    if (!code) continue;
    const returnedState = params.get("state");
    if (returnedState && expectedState && returnedState !== expectedState) {
      throw new SeatCupraIdkError("SEAT/CUPRA IDK callback state mismatch");
    }
    return code;
  }
  return undefined;
}

class SeatCupraIdkAuth {
  constructor({ brand, username, password, request, logger }) {
    this.brand = brand;
    this.username = username;
    this.password = password;
    this.request = request;
    this.logger = logger || { debug() {} };
  }

  headers(contentType) {
    return {
      Accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
      "User-Agent": this.brand.oauthUserAgent,
      ...(contentType ? { "Content-Type": contentType } : {}),
    };
  }

  requestAsync(options) {
    return new Promise((resolve, reject) => this.request(options, (error, response, body) => {
      if (error) return reject(new SeatCupraIdkError("SEAT/CUPRA IDK network request failed"));
      resolve({ status: response.statusCode, headers: response.headers || {}, body: String(body || "") });
    }));
  }

  async requestBrowser(options) {
    return this.requestAsync({
      jar: this.jar,
      gzip: true,
      followRedirect: false,
      headers: this.headers(options.contentType),
      ...options,
    });
  }

  async followBrowser(startUrl, initialResponse, { submitForms = true } = {}) {
    const appPrefix = this.brand.redirectUri.split("://")[0] + "://";
    let url = startUrl;
    let response = initialResponse;
    for (let hop = 0; hop < 20; hop++) {
      if (url.startsWith(appPrefix)) return { url, body: "" };
      if (!response) response = await this.requestBrowser({ method: "GET", url });
      if (response.status >= 300 && response.status < 400 && response.headers.location) {
        url = new URL(response.headers.location, url).toString();
        response = undefined;
        continue;
      }
      if (response.status === 200) {
        const bodyLower = response.body.toLowerCase();
        if (/captcha|two-factor|email-otp|email-code/.test(bodyLower)) {
          throw new SeatCupraIdkError("SEAT/CUPRA IDK login requires additional verification");
        }
        if (/terms-and-conditions|termsandconditions/.test(bodyLower)) {
          throw new SeatCupraIdkError("SEAT/CUPRA terms must be accepted in the official app");
        }
        if (/wrong-email-credentials|wrong-credentials/.test(bodyLower)) {
          throw new SeatCupraIdkError("SEAT/CUPRA IDK credentials were rejected");
        }
        const form = parseHtmlForm(response.body);
        if (!submitForms || !form || !form.action) return { url, body: response.body };
        const action = new URL(form.action, url).toString();
        response = await this.requestBrowser({
          method: "POST",
          url: action,
          contentType: "application/x-www-form-urlencoded",
          form: form.fields,
        });
        url = action;
        continue;
      }
      if (response.status === 429) throw new SeatCupraIdkError("SEAT/CUPRA IDK login rate limited", { status: 429 });
      throw new SeatCupraIdkError(`SEAT/CUPRA IDK browser flow failed with HTTP ${response.status}`, { status: response.status });
    }
    throw new SeatCupraIdkError("SEAT/CUPRA IDK browser flow exceeded redirect limit");
  }

  async authenticate() {
    if (!this.username || !this.password) throw new SeatCupraIdkError("SEAT/CUPRA username/password not configured");
    this.jar = this.request.jar();
    const pkce = createSeatCupraPkce();
    const authorizeUrl = buildSeatCupraAuthorizeUrl(this.brand, pkce);
    const loginPage = await this.followBrowser(authorizeUrl, undefined, { submitForms: false });
    const loginUrl = loginPage.url;
    const form = parseHtmlForm(loginPage.body);
    const auth0State = form && form.fields.state || new URL(loginUrl).searchParams.get("state");
    if (!auth0State || !loginUrl.includes("/u/login")) {
      throw new SeatCupraIdkError("SEAT/CUPRA IDK Auth0 login page was not available");
    }

    const loginEndpoint = new URL("/u/login", loginUrl);
    loginEndpoint.searchParams.set("state", auth0State);
    const loginForm = { username: this.username, password: this.password, state: auth0State };
    let loginResponse = await this.requestBrowser({
      method: "POST",
      url: loginEndpoint.toString(),
      contentType: "application/x-www-form-urlencoded",
      form: loginForm,
    });
    if (loginResponse.status === 400) {
      loginResponse = await this.requestBrowser({
        method: "POST",
        url: loginEndpoint.toString(),
        contentType: "application/json",
        body: JSON.stringify(loginForm),
      });
    }
    if (loginResponse.status === 401 || loginResponse.status === 400) {
      throw new SeatCupraIdkError("SEAT/CUPRA IDK credentials were rejected", { status: loginResponse.status });
    }
    const callback = await this.followBrowser(loginEndpoint.toString(), loginResponse);
    const code = extractSeatCupraAuthorizationCode(callback.url, this.brand.redirectUri, pkce.state);
    if (!code) throw new SeatCupraIdkError("SEAT/CUPRA IDK callback contained no authorization code");
    return this.exchangeCode(code, pkce.codeVerifier);
  }

  async tokenRequest(body, fallbackRefreshToken = "") {
    const response = await this.requestAsync({
      method: "POST",
      url: this.brand.idkTokenUrl || IDK_TOKEN_URL,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": this.brand.oauthUserAgent,
      },
      body,
      gzip: true,
      followRedirect: false,
    });
    let payload = {};
    try { payload = JSON.parse(response.body || "{}"); } catch { /* Redacted stable error below. */ }
    if (response.status === 200 && payload.access_token) {
      if (!payload.refresh_token && fallbackRefreshToken) payload.refresh_token = fallbackRefreshToken;
      return payload;
    }
    const errorCode = payload.error || payload.code;
    const safeErrorCode = typeof errorCode === "string" && /^[a-z0-9_.-]{1,80}$/i.test(errorCode)
      ? errorCode
      : "";
    throw new SeatCupraIdkError(
      `SEAT/CUPRA IDK token request failed with HTTP ${response.status}${safeErrorCode ? ` (${safeErrorCode})` : ""}`,
      {
        status: response.status,
        transient: TRANSIENT_TOKEN_STATUSES.has(response.status),
        invalidGrant: response.status === 400 && safeErrorCode === "invalid_grant",
      },
    );
  }

  exchangeCode(code, codeVerifier) {
    return this.tokenRequest(buildSeatCupraTokenBody(this.brand, {
      grantType: "authorization_code",
      code,
      codeVerifier,
    }));
  }

  refresh(refreshToken) {
    return this.tokenRequest(buildSeatCupraTokenBody(this.brand, {
      grantType: "refresh_token",
      refreshToken,
    }), refreshToken);
  }
}

module.exports = {
  IDK_AUTHORIZE_URL,
  IDK_TOKEN_URL,
  SeatCupraIdkAuth,
  SeatCupraIdkError,
  createSeatCupraPkce,
  buildSeatCupraAuthorizeUrl,
  buildSeatCupraTokenBody,
  getSeatCupraAuthStrategy,
  getSeatCupraMissingDeviceRecoveryStrategy,
  decodeJwtMetadata,
  parseHtmlForm,
  extractSeatCupraAuthorizationCode,
};
