import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export function hashToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

export function issueToken() {
  return randomBytes(32).toString("base64url");
}

export function safeEqual(value, expected) {
  const left = createHash("sha256").update(String(value)).digest();
  const right = createHash("sha256").update(String(expected)).digest();
  return timingSafeEqual(left, right);
}

export function getBearerToken(request) {
  const value = request.headers.authorization;
  if (!value || !value.startsWith("Bearer ")) return null;
  const token = value.slice(7).trim();
  return token || null;
}

export function ipv4ToNumber(value) {
  const parts = String(value).split(".");
  if (parts.length !== 4) return null;

  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const number = Number(part);
    if (number < 0 || number > 255) return null;
    result = (result * 256 + number) >>> 0;
  }
  return result;
}

export function parseCidr(value) {
  const [address, prefixText] = String(value).trim().split("/");
  const ip = ipv4ToNumber(address);
  const prefix = Number(prefixText);
  if (ip === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`CIDR IPv4 inválido: ${value}`);
  }

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: ip & mask, mask, prefix };
}

export function isIpv4Allowed(address, cidrs) {
  const ip = ipv4ToNumber(address);
  if (ip === null) return false;
  return cidrs.some(({ network, mask }) => (ip & mask) === network);
}

export function numberToIpv4(value) {
  const number = value >>> 0;
  return [24, 16, 8, 0]
    .map((shift) => (number >>> shift) & 0xff)
    .join(".");
}

export function translateIpv4(address, translations) {
  const ip = ipv4ToNumber(address);
  if (ip === null) return null;

  for (const translation of translations) {
    if ((ip & translation.source.mask) !== translation.source.network) continue;
    const hostBits = ip & (~translation.source.mask >>> 0);
    return numberToIpv4((translation.target.network | hostBits) >>> 0);
  }

  return address;
}

export function isOriginAllowed(origin, allowedOrigins) {
  return Boolean(origin && allowedOrigins.has(origin));
}
