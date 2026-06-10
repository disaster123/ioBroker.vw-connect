// @ts-nocheck
"use strict";

const SEAT_CUPRA_BRANDS = {
  seat: {
    clientId: "99a5b77d-bd88-4d53-b4e5-a539c60694a3@apps_vw-dilab_com",
    redirectUri: "seat://oauth-callback",
    scope: "openid profile address phone email birthdate nickname",
    oauthUserAgent: "OLASeat/2.13.3 (Android 12; sdk_gphone64_x86_64; Google) Mobile",
    olaUserAgent: "OLASeat/2.13.3 (Android 12; sdk_gphone64_x86_64; Google) Mobile",
    appVersion: "2.17.0",
    exchangeTokenUrl: "https://ola.prod.code.seat.cloud.vwgroup.com/authorization/api/v1/token",
    refreshTokenUrl: "https://ola.prod.code.seat.cloud.vwgroup.com/authorization/api/v1/token",
  },
  seatcupra: {
    clientId: "3c756d46-f1ba-4d78-9f9a-cff0d5292d51@apps_vw-dilab_com",
    redirectUri: "cupra://oauth-callback",
    scope: "openid profile address phone email birthdate nickname",
    oauthUserAgent: "OLACupra/2.15.0 (Android 12; sdk_gphone64_x86_64; Google) Mobile",
    olaUserAgent: "OLACupra/2.15.0 (Android 12; sdk_gphone64_x86_64; Google) Mobile",
    appVersion: "2.15.0",
    exchangeTokenUrl: "https://identity.vwgroup.io/oidc/v1/token",
    refreshTokenUrl: "https://ola.prod.code.seat.cloud.vwgroup.com/authorization/api/v1/token",
    clientSecret: "eb8814e641c81a2640ad62eeccec11c98effc9bccd4269ab7af338b50a94b3a2",
  },
};

function getSeatCupraBrandConfig(type) {
  return SEAT_CUPRA_BRANDS[type];
}

function getSeatCupraReferenceUserAgent(type) {
  return type === "seat"
    ? "SEATApp/2.5.0 (com.seat.myseat.ola; build:202410171614; iOS 15.8.3) Alamofire/5.7.0 Mobile"
    : "CUPRAApp%20-%20Store/20220503 CFNetwork/1333.0.4 Darwin/21.5.0";
}

function getSeatCupraOlaHeaders(
  type,
  userId,
  accessToken,
  variant = "primary",
  vin,
  { includeIdentifiers = false } = {},
) {
  const config = getSeatCupraBrandConfig(type);
  if (!config) return {};
  const normalizedVariant = variant === "primary" ? "A" : variant;
  const fallback = normalizedVariant === "fallback";
  const referenceUserAgent = normalizedVariant === "B" || normalizedVariant === "D";
  const probeUserId = normalizedVariant === "C" || normalizedVariant === "D";
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/json",
    Authorization: `Bearer ${accessToken}`,
    "app-market": "android",
    "app-brand": type === "seat" ? "seat" : "cupra",
    "app-version": fallback ? "2.16.0" : config.appVersion,
    origin: "app",
    "User-Agent": fallback
      ? type === "seat"
        ? "OLASeat/2.16.0 (Android 14; Pixel 8; Google) Mobile"
        : "OLACupra/2.16.0 (Android 14; Pixel 8; Google) Mobile"
      : referenceUserAgent
        ? getSeatCupraReferenceUserAgent(type)
        : config.olaUserAgent,
  };
  if ((includeIdentifiers || probeUserId) && userId) headers["User-ID"] = userId;
  if (includeIdentifiers && vin) headers.VIN = vin;
  return headers;
}

function getSeatCupraOlaProbeVariants(type, userId, accessToken) {
  return ["A", "B", "C", "D"].map((variant) => ({
    variant,
    headers: getSeatCupraOlaHeaders(type, userId, accessToken, variant),
  }));
}

async function probeSeatCupraOlaHeaders({ candidates, request, logResult }) {
  let selected;
  for (const candidate of candidates) {
    let response;
    try {
      response = await request(candidate);
    } catch {
      logResult(candidate.variant, "network_error", "unknown");
      continue;
    }
    const details = getSeatCupraOlaErrorDetails(response.data);
    logResult(candidate.variant, response.status, details.code);
    if (!selected && [200, 201, 202, 207].includes(response.status)) {
      selected = { variant: candidate.variant, data: response.data };
    }
  }
  return selected;
}

function beginSeatCupraHeaderProbe(runtime, enabled) {
  if (!runtime || !enabled || runtime.seatCupraMycarProbeAttempted) return false;
  runtime.seatCupraMycarProbeAttempted = true;
  return true;
}

function applySeatCupraProbeSelection(runtime, result) {
  if (!runtime || !result || !result.variant) return undefined;
  runtime.seatCupraOlaHeaderVariant = result.variant;
  return result.variant;
}

function isSeatCupraEndpointResultOk(result) {
  return Boolean(result && result.ok === true && result.data != null);
}

async function pollSeatCupraEndpoints(endpoints, requestEndpoint, shouldStop = () => false) {
  const results = [];
  for (const endpoint of endpoints) {
    if (shouldStop()) break;
    try {
      results.push(await requestEndpoint(endpoint));
    } catch {
      results.push({
        ok: false,
        path: endpoint.path,
        status: "request_error",
        code: "unknown",
        message: "request failed",
        category: "request",
      });
    }
  }
  return results;
}

function getSeatCupraDefaultStatusEndpoints(userId, vin) {
  const baseUrl = "https://ola.prod.code.seat.cloud.vwgroup.com";
  return [
    {
      url: `${baseUrl}/v5/users/${userId}/vehicles/${vin}/mycar`,
      path: "status",
    },
    {
      url: `${baseUrl}/v1/vehicles/${vin}/parkingposition`,
      path: "parkingposition",
    },
    { url: `${baseUrl}/v1/vehicles/${vin}/ranges`, path: "ranges" },
    { url: `${baseUrl}/v2/vehicles/${vin}/status`, path: "statusv2" },
    { url: `${baseUrl}/v1/vehicles/${vin}/charging/status`, path: "charging" },
    { url: `${baseUrl}/v1/vehicles/${vin}/charging/info`, path: "charging.info" },
    { url: `${baseUrl}/v1/vehicles/${vin}/climatisation/status`, path: "climatisation" },
    { url: `${baseUrl}/v1/vehicles/${vin}/maintenance`, path: "maintenance" },
    { url: `${baseUrl}/v1/vehicles/${vin}/mileage`, path: "mileage" },
    {
      url: `${baseUrl}/v3/vehicles/${vin}/warninglights`,
      path: "warninglights",
      options: { forceIndex: true },
    },
  ];
}

function formatSeatCupraOlaRequest(method, url, headers, tokenOrigin = "unknown") {
  const pathname = new URL(url, "https://ola.invalid").pathname;
  return (
    `SEAT/CUPRA OLA request: ${String(method).toUpperCase()} ${pathname} ` +
    `brand=${headers["app-brand"] || "unknown"} appVersion=${headers["app-version"] || "unknown"} ` +
    `userAgent=${JSON.stringify(headers["User-Agent"] || "")} tokenOrigin=${tokenOrigin} ` +
    `auth=${headers.Authorization ? "yes" : "no"}`
  );
}

const SEAT_CUPRA_SERVER_RETRY_DELAYS = [3000, 6000, 12000];

function isSeatCupraRetryableServerStatus(status) {
  return status === 500 || status === 502 || status === 503 || status === 504;
}

async function requestSeatCupraWithServerRetry({
  request,
  sleep = (delay) => new Promise((resolve) => setTimeout(resolve, delay)),
  retryDelays = SEAT_CUPRA_SERVER_RETRY_DELAYS,
  onAttempt = () => {},
  onRetry = () => {},
}) {
  let response;
  for (let attempt = 0; attempt <= retryDelays.length; attempt++) {
    onAttempt(attempt + 1);
    response = await request();
    if (!isSeatCupraRetryableServerStatus(response.status) || attempt === retryDelays.length) return response;
    const delay = retryDelays[attempt];
    onRetry({ attempt: attempt + 1, delay, status: response.status });
    await sleep(delay);
  }
  return response;
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

function isSeatCupraMycarEndpoint(pathname) {
  return typeof pathname === "string" && /^\/v5\/users\/[^/]+\/vehicles\/[^/]+\/mycar$/.test(pathname);
}

function isSeatCupraDetailEndpoint(pathname) {
  if (typeof pathname !== "string") return false;
  return (
    isSeatCupraMycarEndpoint(pathname) ||
    /^\/v1\/vehicles\/[^/]+\/(parkingposition|ranges|maintenance|mileage)$/.test(pathname) ||
    /^\/v2\/vehicles\/[^/]+\/status$/.test(pathname) ||
    /^\/v1\/vehicles\/[^/]+\/(charging\/(status|info)|climatisation\/status)$/.test(pathname)
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
  if (isSeatCupraMycarEndpoint(pathname)) return "skip-mycar";
  if (isSeatCupraOptionalEndpoint(pathname)) return "skip-optional";
  if (isSeatCupraDetailEndpoint(pathname)) return "skip-detail";
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
  if (action === "skip-mycar" || action === "skip-optional" || action === "skip-detail") {
    await recordSkipped(method, pathname, status, data);
    const details = getSeatCupraOlaErrorDetails(data);
    if (action === "skip-mycar") {
      logWarning(
        `SEAT/CUPRA OLA mycar skipped: status=${status} code=${details.code}; continuing with other endpoints`,
      );
    } else if (action === "skip-optional") {
      logWarning(
        `SEAT/CUPRA optional OLA endpoint skipped after fresh login: ` +
          `${String(method).toUpperCase()} ${pathname} status=${status} code=${details.code}`,
      );
    }
    completeRecovery();
    return {
      skipped: true,
      stopCycle: false,
      category: action === "skip-mycar"
        ? "mycar"
        : action === "skip-optional" ? "optional" : "missing-device-token",
    };
  }
  const message =
    `SEAT/CUPRA core OLA endpoint rejected token after fresh login: ` +
    `${String(method).toUpperCase()} ${pathname} status=${status} code=missing-device-token`;
  logError(message);
  return { skipped: false, stopCycle: true, message };
}

function summarizeSeatCupraEndpointResults(results, tokenOrigin, timestamp = new Date()) {
  const successful = results.filter(isSeatCupraEndpointResultOk);
  const failed = results.filter((result) => !isSeatCupraEndpointResultOk(result));
  const missingDevice = failed.filter((result) => result.code === "missing-device-token");
  const first = failed[0];
  return {
    tokenOrigin: tokenOrigin || "unknown",
    success: successful.length,
    failed: failed.length,
    missingDevice: missingDevice.length,
    firstFailure: first ? `GET ${first.pathname}` : "",
    firstFailureStatus: first ? first.status : "",
    firstFailureCode: first ? first.code : "",
    lastUpdate: timestamp.toISOString(),
  };
}

function isMissingDeviceToken(data) {
  if (!data) return false;
  if (typeof data === "string") return /missing-device-token/i.test(data);
  return data.code === "missing-device-token" || data.error === "missing-device-token";
}

function shouldRecoverSeatCupraAuthentication(status, data) {
  return status === 403 && isMissingDeviceToken(data);
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
  isSeatCupraMycarEndpoint,
  isSeatCupraDetailEndpoint,
  isSeatCupraOptionalEndpoint,
  getSeatCupraSkippedEndpointKey,
  decideSeatCupraRepeatedMissingDeviceToken,
  createSeatCupraSkippedEndpointDetail,
  handleSeatCupraRepeatedMissingDeviceToken,
  getSeatCupraBrandConfig,
  getSeatCupraReferenceUserAgent,
  getSeatCupraOlaHeaders,
  getSeatCupraOlaProbeVariants,
  probeSeatCupraOlaHeaders,
  beginSeatCupraHeaderProbe,
  applySeatCupraProbeSelection,
  isSeatCupraEndpointResultOk,
  pollSeatCupraEndpoints,
  getSeatCupraDefaultStatusEndpoints,
  formatSeatCupraOlaRequest,
  SEAT_CUPRA_SERVER_RETRY_DELAYS,
  isSeatCupraRetryableServerStatus,
  requestSeatCupraWithServerRetry,
  summarizeSeatCupraEndpointResults,
  isMissingDeviceToken,
  shouldRecoverSeatCupraAuthentication,
};
