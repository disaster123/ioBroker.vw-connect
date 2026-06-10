// @ts-nocheck
"use strict";

const DEVICE_AUTHORIZATION_URL = "https://identity.vwgroup.io/oidc/v1/device_authorization";
const TOKEN_URL = "https://identity.vwgroup.io/oidc/v1/token";
const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

function redactSecrets(value) {
  if (value == null) return value;
  let text = typeof value === "string" ? value : JSON.stringify(value);
  text = text.replace(/Bearer\s+[A-Za-z0-9._~+/-]+/gi, "Bearer [REDACTED]");
  text = text.replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED_JWT]");
  text = text.replace(
    /(["']?(?:access_token|refresh_token|id_token|device_code|client_secret)["']?\s*[:=]\s*["']?)[^"'&\s,}]+/gi,
    "$1[REDACTED]",
  );
  return text;
}

class OAuthDeviceGrantError extends Error {
  constructor(message, code, status) {
    super(message);
    this.name = "OAuthDeviceGrantError";
    this.code = code;
    this.status = status;
  }
}

class OAuthDeviceGrant {
  constructor({ clientId, scope, userAgent, httpClient, sleep, now, logger }) {
    this.clientId = clientId;
    this.scope = scope;
    this.userAgent = userAgent;
    this.httpClient = httpClient;
    this.sleep = sleep || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.now = now || (() => Date.now());
    this.logger = logger || {};
  }

  headers() {
    return {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      ...(this.userAgent ? { "User-Agent": this.userAgent } : {}),
    };
  }

  async requestDeviceCode() {
    const body = new URLSearchParams({ client_id: this.clientId, scope: this.scope }).toString();
    const response = await this.httpClient({
      method: "post",
      url: DEVICE_AUTHORIZATION_URL,
      headers: this.headers(),
      data: body,
      validateStatus: () => true,
    });
    if (response.status !== 200) {
      const code = response.data && response.data.error;
      throw new OAuthDeviceGrantError(
        `Device authorization failed (${response.status}, ${code || "unknown_error"})`,
        code,
        response.status,
      );
    }
    const data = response.data || {};
    const required = ["device_code", "user_code", "verification_uri", "expires_in"];
    const missing = required.filter((field) => data[field] == null);
    if (missing.length) {
      throw new OAuthDeviceGrantError(`Device authorization response missing: ${missing.join(", ")}`);
    }
    return {
      device_code: String(data.device_code),
      user_code: String(data.user_code),
      verification_uri: String(data.verification_uri),
      verification_uri_complete: String(data.verification_uri_complete || data.verification_uri),
      expires_in: Number(data.expires_in),
      interval: Number(data.interval || 5),
    };
  }

  async pollForTokens(deviceCode, { interval = 5, expiresIn = 300, onSlowDown } = {}) {
    const deadline = this.now() + Math.max(1, Number(expiresIn)) * 1000;
    let intervalSeconds = Math.max(1, Number(interval));
    const body = new URLSearchParams({
      grant_type: DEVICE_CODE_GRANT,
      device_code: deviceCode,
      client_id: this.clientId,
    }).toString();

    while (this.now() < deadline) {
      await this.sleep(intervalSeconds * 1000);
      let response;
      try {
        response = await this.httpClient({
          method: "post",
          url: TOKEN_URL,
          headers: this.headers(),
          data: body,
          validateStatus: () => true,
        });
      } catch (error) {
        if (this.logger.debug) this.logger.debug("Device token poll network error; retrying: " + error.message);
        continue;
      }
      const data = response.data || {};
      if (response.status === 200 && data.access_token) return data;

      if (data.error === "authorization_pending") continue;
      if (data.error === "slow_down") {
        intervalSeconds += 5;
        if (onSlowDown) onSlowDown(intervalSeconds);
        continue;
      }
      if (data.error === "expired_token") {
        throw new OAuthDeviceGrantError("Device authorization code expired", data.error, response.status);
      }
      throw new OAuthDeviceGrantError(
        `Device token polling failed (${response.status}, ${data.error || "unknown_error"})`,
        data.error,
        response.status,
      );
    }
    throw new OAuthDeviceGrantError("Device authorization polling timed out", "expired_token");
  }

  async refreshToken(refreshToken, { clientSecret, retryInvalidClientWithSecret = false } = {}) {
    const request = async (includeSecret) => {
      const params = {
        client_id: this.clientId,
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      };
      if (includeSecret && clientSecret) params.client_secret = clientSecret;
      return this.httpClient({
        method: "post",
        url: TOKEN_URL,
        headers: this.headers(),
        data: new URLSearchParams(params).toString(),
        validateStatus: () => true,
      });
    };

    let response = await request(false);
    if (
      retryInvalidClientWithSecret &&
      clientSecret &&
      response.data &&
      response.data.error === "invalid_client"
    ) {
      response = await request(true);
    }
    if (response.status !== 200 || !response.data || !response.data.access_token) {
      const code = response.data && response.data.error;
      throw new OAuthDeviceGrantError(
        `Refresh token request failed (${response.status}, ${code || "unknown_error"})`,
        code,
        response.status,
      );
    }
    return response.data;
  }
}

module.exports = {
  DEVICE_AUTHORIZATION_URL,
  TOKEN_URL,
  DEVICE_CODE_GRANT,
  OAuthDeviceGrant,
  OAuthDeviceGrantError,
  redactSecrets,
};
