// @ts-nocheck
"use strict";

const crypto = require("crypto");

const IDK_AUTHORIZE_URL = "https://identity.vwgroup.io/oidc/v1/authorize";
const IDENTITY_TOKEN_URL = "https://identity.vwgroup.io/oidc/v1/token";
const OLA_TOKEN_URL = "https://ola.prod.code.seat.cloud.vwgroup.com/authorization/api/v1/token";
const BROWSER_USER_AGENT =
  "Mozilla/5.0 (Linux; Android 14; SM-S908B) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36";
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
  const body = new URLSearchParams({ client_id: brand.clientId, grant_type: grant.grantType });
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

function decodeJwtMetadataSafe(token, label, strategy) {
  const exists = typeof token === "string" && token.length > 0;
  const metadata = { label, strategy, exists, len: exists ? token.length : 0 };
  if (!exists) return metadata;
  const part = token.split(".")[1];
  if (!part) return metadata;
  try {
    const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    const payload = JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
    for (const key of ["exp", "aud", "azp", "iss", "scope", "scp"]) {
      if (payload[key] !== undefined) metadata[key] = payload[key];
    }
  } catch {
    // Metadata is diagnostic only; malformed or opaque tokens are valid inputs.
  }
  return metadata;
}

function decodeJwtMetadata(token, strategy) {
  const { label, exists, len, ...metadata } = decodeJwtMetadataSafe(token, "token", strategy);
  return metadata;
}

async function upgradeSeatCupraClassicTokens(tokens, refresh) {
  const identityTokens = { ...tokens };
  if (!identityTokens.refresh_token) {
    return { tokens: identityTokens, origin: "classic_idk_identity_exchange", outcome: "not_available" };
  }
  try {
    const refreshed = await refresh(identityTokens.refresh_token);
    return {
      tokens: {
        ...identityTokens,
        ...refreshed,
        refresh_token: refreshed.refresh_token || identityTokens.refresh_token,
        id_token: refreshed.id_token || identityTokens.id_token,
      },
      origin: "classic_idk_ola_refresh",
      outcome: "upgraded",
    };
  } catch (error) {
    return {
      tokens: identityTokens,
      origin: "classic_idk_identity_exchange",
      outcome: error && error.transient ? "transient" : "rejected",
      error,
    };
  }
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
  const sources = [
    parsed.searchParams,
    new URLSearchParams(parsed.pathname.replace(/^\/?\??/, "")),
    new URLSearchParams(parsed.hash.replace(/^#/, "")),
  ];
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

function endpointLabel(url) {
  return url === IDENTITY_TOKEN_URL ? "identity" : "ola";
}

function isAuth0SpaResponse(body) {
  const text = String(body || "").toLowerCase();
  return !text || /wrong-email-credentials|wrong-credentials|__next_data__|id=["']root["']/.test(text);
}

class SeatCupraIdkAuth {
  constructor({ brand, username, password, request, logger }) {
    this.brand = brand;
    this.username = username;
    this.password = password;
    this.request = request;
    this.logger = logger || {};
  }

  log(level, message) {
    if (typeof this.logger[level] === "function") this.logger[level](message);
  }

  browserHeaders({ contentType, userAgent, origin, referer } = {}) {
    return {
      Accept: "text/html,application/xhtml+xml,*/*",
      "User-Agent": userAgent || this.brand.oauthUserAgent,
      ...(contentType ? { "Content-Type": contentType } : {}),
      ...(origin ? { Origin: origin } : {}),
      ...(referer ? { Referer: referer } : {}),
    };
  }

  requestAsync(options) {
    return new Promise((resolve, reject) => this.request(options, (error, response, body) => {
      if (error) return reject(new SeatCupraIdkError("SEAT/CUPRA IDK network request failed"));
      resolve({
        status: response.statusCode,
        headers: response.headers || {},
        body: String(body || ""),
        url: response.request && response.request.uri && response.request.uri.href || options.url,
      });
    }));
  }

  requestBrowser(options) {
    const { contentType, userAgent, origin, referer, headers, ...requestOptions } = options;
    return this.requestAsync({
      jar: this.jar,
      gzip: true,
      followRedirect: false,
      ...requestOptions,
      headers: {
        ...this.browserHeaders({ contentType, userAgent, origin, referer }),
        ...headers,
      },
    });
  }

  challengeType(url) {
    const value = String(url || "").toLowerCase();
    if (/\/u\/(email-challenge|mfa)(?:[/?#]|$)/.test(value)) return "mfa";
    if (/terms-and-conditions|termsandconditions/.test(value)) return "terms";
    if (/consent\/marketing|\/u\/consent|cupraid\.vwgroup\.io/.test(value)) return "marketing";
    return undefined;
  }

  async skipMarketingConsent(consentUrl) {
    const callback = new URL(consentUrl).searchParams.get("callback");
    if (!callback) return undefined;
    const callbackUrl = new URL(callback, consentUrl).toString();
    if (callbackUrl.startsWith(this.brand.redirectUri.split("://")[0] + "://")) return callbackUrl;
    const response = await this.requestBrowser({ method: "GET", url: callbackUrl });
    if (response.status >= 300 && response.status < 400 && response.headers.location) {
      return new URL(response.headers.location, callbackUrl).toString();
    }
    if (callbackUrl.startsWith(this.brand.redirectUri.split("://")[0] + "://")) return callbackUrl;
    return undefined;
  }

  async handleChallengeUrl(url) {
    const challenge = this.challengeType(url);
    if (challenge === "mfa") {
      throw new SeatCupraIdkError("SEAT/CUPRA IDK login requires additional verification in the official app");
    }
    if (challenge === "terms") {
      throw new SeatCupraIdkError("SEAT/CUPRA terms and conditions must be accepted in the official app");
    }
    if (challenge === "marketing") {
      const skipped = await this.skipMarketingConsent(url);
      if (skipped) return skipped;
      throw new SeatCupraIdkError("SEAT/CUPRA marketing consent requires confirmation in the official app");
    }
    return url;
  }

  inspectResponseBody(body) {
    const value = String(body || "").toLowerCase();
    if (/email-challenge|email-otp|email-code|two-factor|\/u\/mfa|captcha/.test(value)) {
      throw new SeatCupraIdkError("SEAT/CUPRA IDK login requires additional verification in the official app");
    }
    if (/terms-and-conditions|termsandconditions/.test(value)) {
      throw new SeatCupraIdkError("SEAT/CUPRA terms and conditions must be accepted in the official app");
    }
  }

  async followBrowser(startUrl, initialResponse, { submitForms = true } = {}) {
    const appPrefix = this.brand.redirectUri.split("://")[0] + "://";
    let url = startUrl;
    let response = initialResponse;
    for (let hop = 0; hop < 20; hop++) {
      url = await this.handleChallengeUrl(url);
      if (url.startsWith(appPrefix)) return { url, body: "" };
      if (!response) response = await this.requestBrowser({ method: "GET", url });
      if (response.status >= 300 && response.status < 400 && response.headers.location) {
        url = new URL(response.headers.location, url).toString();
        response = undefined;
        continue;
      }
      if (response.status === 200) {
        this.inspectResponseBody(response.body);
        const form = parseHtmlForm(response.body);
        if (!submitForms || !form || !form.action) return { url: response.url || url, body: response.body };
        const action = new URL(form.action, url).toString();
        response = await this.requestBrowser({
          method: "POST",
          url: action,
          contentType: "application/x-www-form-urlencoded",
          origin: "https://identity.vwgroup.io",
          referer: url,
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

  async getAuthorizeLanding(authorizeUrl) {
    let response = await this.requestBrowser({ method: "GET", url: authorizeUrl });
    if (response.status === 401 || response.status === 403) {
      response = await this.requestBrowser({ method: "GET", url: authorizeUrl, userAgent: BROWSER_USER_AGENT });
    }
    if (response.status === 401 || response.status === 403) {
      throw new SeatCupraIdkError(`SEAT/CUPRA authorization page rejected the request with HTTP ${response.status}`, {
        status: response.status,
      });
    }
    return this.followBrowser(authorizeUrl, response, { submitForms: false });
  }

  async authenticateAuth0(loginPage, pkce) {
    const loginUrl = loginPage.url;
    const form = parseHtmlForm(loginPage.body);
    const auth0State = form && form.fields.state || new URL(loginUrl).searchParams.get("state");
    if (!auth0State) throw new SeatCupraIdkError("SEAT/CUPRA IDK Auth0 state was not available");

    const loginEndpoint = new URL("/u/login", loginUrl);
    loginEndpoint.searchParams.set("state", auth0State);
    const loginForm = { username: this.username, password: this.password, state: auth0State };
    let loginResponse = await this.requestBrowser({
      method: "POST",
      url: loginEndpoint.toString(),
      contentType: "application/x-www-form-urlencoded",
      origin: "https://identity.vwgroup.io",
      referer: loginUrl,
      form: loginForm,
    });
    if (loginResponse.status === 400 && isAuth0SpaResponse(loginResponse.body)) {
      loginResponse = await this.requestBrowser({
        method: "POST",
        url: loginEndpoint.toString(),
        contentType: "application/json",
        origin: "https://identity.vwgroup.io",
        referer: loginUrl,
        body: JSON.stringify(loginForm),
      });
    }
    if (loginResponse.status === 401 || loginResponse.status === 400) {
      throw new SeatCupraIdkError("SEAT/CUPRA IDK credentials were rejected", { status: loginResponse.status });
    }
    const callback = await this.followBrowser(loginEndpoint.toString(), loginResponse);
    return this.exchangeCallback(callback.url, pkce);
  }

  async authenticateLegacy(loginPage, pkce) {
    const initialForm = parseHtmlForm(loginPage.body);
    if (!initialForm || !Object.keys(initialForm.fields).length) {
      throw new SeatCupraIdkError("SEAT/CUPRA legacy IDK login form was not available");
    }
    const signinBase = `https://identity.vwgroup.io/signin-service/v1/${this.brand.clientId}`;
    const identifierUrl = new URL(initialForm.action || `${signinBase}/login/identifier`, loginPage.url).toString();
    const identifierResponse = await this.requestBrowser({
      method: "POST",
      url: identifierUrl,
      contentType: "application/x-www-form-urlencoded",
      origin: "https://identity.vwgroup.io",
      referer: loginPage.url,
      form: { ...initialForm.fields, email: this.username },
      followAllRedirects: true,
    });
    if (identifierResponse.status !== 200) {
      throw new SeatCupraIdkError(`SEAT/CUPRA legacy identifier request failed with HTTP ${identifierResponse.status}`, {
        status: identifierResponse.status,
      });
    }
    this.inspectResponseBody(identifierResponse.body);
    const passwordForm = parseHtmlForm(identifierResponse.body);
    const hmac = (identifierResponse.body.match(/"hmac"\s*:\s*"([0-9a-f]+)"/i) || [])[1];
    const passwordFields = hmac
      ? { ...initialForm.fields, hmac }
      : { ...(passwordForm && passwordForm.fields || {}) };
    const passwordUrl = new URL(
      passwordForm && passwordForm.action || identifierUrl.replace("identifier", "authenticate"),
      identifierUrl,
    ).toString();
    const passwordResponse = await this.requestBrowser({
      method: "POST",
      url: passwordUrl,
      contentType: "application/x-www-form-urlencoded",
      origin: "https://identity.vwgroup.io",
      referer: identifierResponse.url || identifierUrl,
      form: { ...passwordFields, email: this.username, password: this.password },
    });
    if (passwordResponse.status === 401 || passwordResponse.status === 400) {
      throw new SeatCupraIdkError("SEAT/CUPRA IDK credentials were rejected", { status: passwordResponse.status });
    }
    this.inspectResponseBody(passwordResponse.body);
    const callback = await this.followBrowser(passwordUrl, passwordResponse);
    return this.exchangeCallback(callback.url, pkce);
  }

  async exchangeCallback(callbackUrl, pkce) {
    const code = extractSeatCupraAuthorizationCode(callbackUrl, this.brand.redirectUri, pkce.state);
    if (!code) throw new SeatCupraIdkError("SEAT/CUPRA IDK callback contained no authorization code");
    return this.exchangeCode(code, pkce.codeVerifier);
  }

  async authenticate() {
    if (!this.username || !this.password) throw new SeatCupraIdkError("SEAT/CUPRA username/password not configured");
    this.jar = this.request.jar();
    const pkce = createSeatCupraPkce();
    const loginPage = await this.getAuthorizeLanding(buildSeatCupraAuthorizeUrl(this.brand, pkce));
    if (loginPage.url.includes("/u/login")) return this.authenticateAuth0(loginPage, pkce);
    return this.authenticateLegacy(loginPage, pkce);
  }

  async tokenRequest(url, body, fallbackRefreshToken = "") {
    const response = await this.requestAsync({
      method: "POST",
      url,
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
    try { payload = JSON.parse(response.body || "{}"); } catch { /* Stable redacted error below. */ }
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
    const url = this.brand.exchangeTokenUrl || IDENTITY_TOKEN_URL;
    this.log("info", `SEAT/CUPRA classic IDK token exchange endpoint: ${endpointLabel(url)}`);
    return this.tokenRequest(url, buildSeatCupraTokenBody(this.brand, {
      grantType: "authorization_code",
      code,
      codeVerifier,
    }));
  }

  refresh(refreshToken) {
    const url = this.brand.refreshTokenUrl || OLA_TOKEN_URL;
    this.log("info", `SEAT/CUPRA classic IDK refresh endpoint: ${endpointLabel(url)}`);
    return this.tokenRequest(url, buildSeatCupraTokenBody(this.brand, {
      grantType: "refresh_token",
      refreshToken,
    }), refreshToken);
  }
}

module.exports = {
  IDK_AUTHORIZE_URL,
  IDENTITY_TOKEN_URL,
  OLA_TOKEN_URL,
  BROWSER_USER_AGENT,
  SeatCupraIdkAuth,
  SeatCupraIdkError,
  createSeatCupraPkce,
  buildSeatCupraAuthorizeUrl,
  buildSeatCupraTokenBody,
  getSeatCupraAuthStrategy,
  getSeatCupraMissingDeviceRecoveryStrategy,
  decodeJwtMetadataSafe,
  decodeJwtMetadata,
  upgradeSeatCupraClassicTokens,
  parseHtmlForm,
  extractSeatCupraAuthorizationCode,
};
