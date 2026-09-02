import { parseCidr } from "./security.js";

function integer(name, fallback, minimum, maximum) {
  const raw = process.env[name];
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} deve ser um inteiro entre ${minimum} e ${maximum}`);
  }
  return value;
}

function csv(name, fallback) {
  return String(process.env[name] ?? fallback)
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

export function loadConfig() {
  const apiKey = String(process.env.GATEWAY_API_KEY ?? "");
  if (apiKey.length < 32) {
    throw new Error("GATEWAY_API_KEY deve conter pelo menos 32 caracteres");
  }

  const publicBaseUrl = String(process.env.PUBLIC_BASE_URL ?? "").replace(/\/$/, "");
  if (!/^https:\/\//.test(publicBaseUrl)) {
    throw new Error("PUBLIC_BASE_URL deve usar HTTPS");
  }

  const allowedOrigins = new Set(csv("ALLOWED_ORIGINS", ""));
  if (allowedOrigins.size === 0) {
    throw new Error("Configure ao menos uma origem em ALLOWED_ORIGINS");
  }

  const allowedCidrs = csv(
    "ALLOWED_SSH_CIDRS",
    "172.18.18.0/24,172.17.17.0/24",
  ).map(parseCidr);

  const allowedPorts = new Set(
    csv("ALLOWED_SSH_PORTS", "22333").map((value) => {
      const port = Number(value);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`Porta SSH inválida: ${value}`);
      }
      return port;
    }),
  );

  return {
    port: integer("PORT", 3000, 1, 65535),
    apiKey,
    publicBaseUrl,
    allowedOrigins,
    allowedCidrs,
    allowedPorts,
    tokenTtlMs: integer("SESSION_TOKEN_TTL_SECONDS", 60, 15, 300) * 1000,
    sshConnectTimeoutMs:
      integer("SSH_CONNECT_TIMEOUT_SECONDS", 10, 3, 60) * 1000,
    sshSessionMaxMs:
      integer("SSH_SESSION_MAX_SECONDS", 7200, 60, 14400) * 1000,
    maxPendingSessions: integer("MAX_PENDING_SESSIONS", 100, 1, 1000),
    maxActiveSessions: integer("MAX_ACTIVE_SESSIONS", 20, 1, 200),
    maxRequestBytes: 16 * 1024,
    maxWebSocketMessageBytes: 64 * 1024,
  };
}

