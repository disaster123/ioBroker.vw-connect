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

function isMissingDeviceToken(data) {
  if (!data) return false;
  if (typeof data === "string") return /missing-device-token/i.test(data);
  return data.code === "missing-device-token" || data.error === "missing-device-token";
}

module.exports = { getSeatCupraBrandConfig, getSeatCupraOlaHeaders, isMissingDeviceToken };
