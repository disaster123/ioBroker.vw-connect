// @ts-nocheck
"use strict";

const SEAT_CUPRA_BRANDS = {
  seat: {
    clientId: "99a5b77d-bd88-4d53-b4e5-a539c60694a3@apps_vw-dilab_com",
    redirectUri: "seat://oauth-callback",
    scope: "openid profile address phone email birthdate nickname",
    oauthUserAgent: "OLASeat/2.13.3 (Android 12; sdk_gphone64_x86_64; Google) Mobile",
    olaUserAgent: "SEATApp/2.5.0 (iPhone; iOS 18.1; Scale/3.00)",
    appVersion: "2.17.0",
  },
  seatcupra: {
    clientId: "3c756d46-f1ba-4d78-9f9a-cff0d5292d51@apps_vw-dilab_com",
    redirectUri: "cupra://oauth-callback",
    scope: "openid profile address phone email birthdate nickname",
    oauthUserAgent: "OLACupra/2.15.0 (Android 12; sdk_gphone64_x86_64; Google) Mobile",
    olaUserAgent: "CUPRAApp%20-%20Store/20220503 CFNetwork/1333.0.4 Darwin/21.5.0",
    appVersion: "2.15.0",
    clientSecret: "eb8814e641c81a2640ad62eeccec11c98effc9bccd4269ab7af338b50a94b3a2",
  },
};

function getSeatCupraBrandConfig(type) {
  return SEAT_CUPRA_BRANDS[type];
}

function getSeatCupraOlaHeaders(type, userId, accessToken, variant = "primary", vin) {
  const config = getSeatCupraBrandConfig(type);
  if (!config) return {};
  const fallback = variant === "fallback";
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/json;charset=utf-8",
    "Accept-Language": "de-de",
    Authorization: `Bearer ${accessToken}`,
    "app-market": "android",
    "app-brand": type === "seat" ? "seat" : "cupra",
    "app-version": fallback ? "2.16.0" : config.appVersion,
    origin: "app",
    "User-Agent": fallback
      ? type === "seat"
        ? "OLASeat/2.16.0 (Android 14; Pixel 8; Google) Mobile"
        : "OLACupra/2.16.0 (Android 14; Pixel 8; Google) Mobile"
      : config.olaUserAgent,
  };
  if (userId) headers["User-ID"] = userId;
  if (vin) headers.VIN = vin;
  return headers;
}

function decodeBase64UrlJson(value) {
  if (typeof value !== "string" || !value) throw new Error("Invalid base64url JSON value");
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
}

function decodeJwtPayload(token) {
  if (typeof token !== "string") return undefined;
  const parts = token.split(".");
  if (parts.length < 2) return undefined;
  try {
    return decodeBase64UrlJson(parts[1]);
  } catch {
    return undefined;
  }
}

function getJwtSubject(token) {
  const payload = decodeJwtPayload(token);
  return payload && typeof payload.sub === "string" && payload.sub ? payload.sub : undefined;
}

async function resolveSeatCupraUserId({ idToken, identityUserInfo, olaUsers }) {
  const tokenSubject = getJwtSubject(idToken);
  if (tokenSubject) return tokenSubject;

  try {
    const identity = await identityUserInfo();
    if (identity && typeof identity.sub === "string" && identity.sub) return identity.sub;
  } catch {
    // Continue with the OLA user endpoint.
  }

  try {
    const ola = await olaUsers();
    const olaUserId = ola && (ola.userId || ola.sub);
    if (typeof olaUserId === "string" && olaUserId) return olaUserId;
  } catch {
    // The caller receives one stable error after all sources are exhausted.
  }

  throw new Error("SEAT/CUPRA user id could not be resolved");
}

function getSeatCupraGarageUrl(userId) {
  if (typeof userId !== "string" || !userId.trim()) {
    throw new Error("SEAT/CUPRA user id could not be resolved");
  }
  return `https://ola.prod.code.seat.cloud.vwgroup.com/v2/users/${encodeURIComponent(userId)}/garage/vehicles`;
}

function clearSeatCupraTokenValues(target) {
  if (!target) return;
  target.atoken = "";
  target.rtoken = "";
  target.seatCupraIdToken = "";
  target.idtoken = "";
  target.seatCupraTokenExpiresAt = 0;
}

function storeSeatCupraTokenValues(config, runtime, tokens, now = Date.now()) {
  config.atoken = tokens.access_token;
  if (tokens.refresh_token) config.rtoken = tokens.refresh_token;
  if (tokens.id_token) {
    config.seatCupraIdToken = tokens.id_token;
    config.idtoken = tokens.id_token;
  }
  const expiresAt = now + Number(tokens.expires_in || 3600) * 1000;
  config.seatCupraTokenExpiresAt = expiresAt;
  runtime.seatCupraTokenExpiresAt = expiresAt;
  return expiresAt;
}

function clearSeatCupraRuntimeTokens(config, runtime) {
  clearSeatCupraTokenValues(config);
  runtime.seatCupraTokenExpiresAt = 0;
  runtime.seatcupraUser = undefined;
}

async function runSeatCupraFreshRecovery({ login, resolveUserId }) {
  await login({ force: true });
  await resolveUserId();
}

async function retrySeatCupraRequestAfterRecovery({ recover, retryRequest }) {
  await recover();
  return retryRequest();
}

function getSeatCupraOlaErrorDetails(data) {
  if (!data) return { code: "unknown", message: "" };
  if (typeof data === "string") return { code: "unknown", message: data };
  return {
    code: String(data.code || data.error || data.errorCode || "unknown"),
    message: String(data.message || data.error_description || data.description || ""),
  };
}

async function startSeatCupraDeviceAuthorization({
  force,
  clearTokens,
  requestDeviceCode,
}) {
  if (force) await clearTokens();
  return requestDeviceCode();
}

function shouldUseSeatCupraRefreshToken(force, refreshToken) {
  return !force && Boolean(refreshToken);
}

function completeSeatCupraMissingDeviceRecovery(state) {
  state.seatCupraForcedReloginAttempted = false;
  state.seatCupraMissingDeviceWarningLogged = false;
}

function failSeatCupraMissingDeviceRecovery(state) {
  state.seatCupraPollingStopped = true;
}

function beginSeatCupraMissingDeviceRecovery(authRetried, recoveryContext) {
  if (authRetried || recoveryContext.recoveryAttempted) return false;
  recoveryContext.recoveryAttempted = true;
  return true;
}

function formatSeatCupraOlaFailure({ method, url, status, data, redact }) {
  const endpoint = new URL(url, "https://ola.invalid").pathname;
  const details = getSeatCupraOlaErrorDetails(data);
  const safeCode = redact(details.code).slice(0, 100);
  const safeMessage = redact(details.message).slice(0, 300);
  return (
    `SEAT/CUPRA OLA request failed: ${String(method).toUpperCase()} ${endpoint} ` +
    `status=${status} code=${safeCode} message=${JSON.stringify(safeMessage)}`
  );
}

function isSeatCupraOptionalEndpoint(pathname) {
  if (typeof pathname !== "string") return false;
  return (
    /^\/v3\/vehicles\/[^/]+\/warninglights$/.test(pathname) ||
    /^\/v1\/vehicles\/[^/]+\/maintenance$/.test(pathname) ||
    /^\/v1\/vehicles\/[^/]+\/parkingposition$/.test(pathname)
  );
}

function getSeatCupraSkippedEndpointKey(method, pathname) {
  return `${String(method).toUpperCase()} ${pathname}`;
}

function decideSeatCupraRepeatedMissingDeviceToken(pathname, recoveryContext) {
  if (isSeatCupraOptionalEndpoint(pathname)) return "skip-optional";
  recoveryContext.stopDetailPolling = true;
  return "stop-cycle";
}

function createSeatCupraSkippedEndpointDetail(method, pathname, status, data, timestamp = new Date()) {
  const details = getSeatCupraOlaErrorDetails(data);
  return {
    method: String(method).toUpperCase(),
    pathname,
    status,
    code: details.code,
    timestamp: timestamp.toISOString(),
  };
}

async function handleSeatCupraRepeatedMissingDeviceToken({
  method,
  pathname,
  status,
  data,
  recoveryContext,
  recordSkipped,
  logWarning,
  logError,
  completeRecovery,
}) {
  const action = decideSeatCupraRepeatedMissingDeviceToken(pathname, recoveryContext);
  if (action === "skip-optional") {
    await recordSkipped(method, pathname, status, data);
    const details = getSeatCupraOlaErrorDetails(data);
    logWarning(
      `SEAT/CUPRA optional OLA endpoint skipped after fresh login: ` +
        `${String(method).toUpperCase()} ${pathname} status=${status} code=${details.code}`,
    );
    completeRecovery();
    return { skipped: true, stopCycle: false };
  }
  const message =
    `SEAT/CUPRA core OLA endpoint rejected token after fresh login: ` +
    `${String(method).toUpperCase()} ${pathname} status=${status} code=missing-device-token`;
  logError(message);
  return { skipped: false, stopCycle: true, message };
}

function isMissingDeviceToken(data) {
  if (!data) return false;
  if (typeof data === "string") return /missing-device-token/i.test(data);
  return data.code === "missing-device-token" || data.error === "missing-device-token";
}

module.exports = {
  decodeBase64UrlJson,
  decodeJwtPayload,
  getJwtSubject,
  resolveSeatCupraUserId,
  getSeatCupraGarageUrl,
  clearSeatCupraTokenValues,
  storeSeatCupraTokenValues,
  clearSeatCupraRuntimeTokens,
  runSeatCupraFreshRecovery,
  retrySeatCupraRequestAfterRecovery,
  getSeatCupraOlaErrorDetails,
  startSeatCupraDeviceAuthorization,
  shouldUseSeatCupraRefreshToken,
  beginSeatCupraMissingDeviceRecovery,
  completeSeatCupraMissingDeviceRecovery,
  failSeatCupraMissingDeviceRecovery,
  formatSeatCupraOlaFailure,
  isSeatCupraOptionalEndpoint,
  getSeatCupraSkippedEndpointKey,
  decideSeatCupraRepeatedMissingDeviceToken,
  createSeatCupraSkippedEndpointDetail,
  handleSeatCupraRepeatedMissingDeviceToken,
  getSeatCupraBrandConfig,
  getSeatCupraOlaHeaders,
  isMissingDeviceToken,
};
