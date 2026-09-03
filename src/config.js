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

function targetTranslations() {
  return csv("SSH_TARGET_TRANSLATIONS", "").map((value) => {
    const parts = value.split("=").map((part) => part.trim());
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      throw new Error(`Tradução SSH inválida: ${value}`);
    }

    const source = parseCidr(parts[0]);
    const target = parseCidr(parts[1]);
    if (source.prefix !== target.prefix) {
      throw new Error(`As redes da tradução devem ter o mesmo prefixo: ${value}`);
    }
    return { source, target };
  });
}

function ports(name, fallback) {
  return new Set(csv(name, fallback).map((value) => {
    const port = Number(value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`Porta inválida em ${name}: ${value}`);
    }
    return port;
  }));
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

  const allowedPorts = ports("ALLOWED_SSH_PORTS", "22333");

  const webfigPublicBaseUrl = String(
    process.env.WEBFIG_PUBLIC_BASE_URL ?? "https://webfig.c3protect.com.br",
  ).replace(/\/$/, "");
  if (!/^https:\/\/[^/]+$/.test(webfigPublicBaseUrl)) {
    throw new Error("WEBFIG_PUBLIC_BASE_URL deve ser uma origem HTTPS válida");
  }

  const webfigReturnUrl = String(
    process.env.WEBFIG_RETURN_URL ?? [...allowedOrigins][0],
  );
  if (!/^https:\/\//.test(webfigReturnUrl)) {
    throw new Error("WEBFIG_RETURN_URL deve usar HTTPS");
  }

  return {
    port: integer("PORT", 3000, 1, 65535),
    apiKey,
    publicBaseUrl,
    allowedOrigins,
    allowedCidrs,
    allowedPorts,
    allowedWebfigPorts: ports("ALLOWED_WEBFIG_PORTS", "1080"),
    targetTranslations: targetTranslations(),
    webfigPublicBaseUrl,
    webfigReturnUrl,
    tokenTtlMs: integer("SESSION_TOKEN_TTL_SECONDS", 60, 15, 300) * 1000,
    sshConnectTimeoutMs:
      integer("SSH_CONNECT_TIMEOUT_SECONDS", 10, 3, 60) * 1000,
    sshCommandTimeoutMs:
      integer("SSH_COMMAND_TIMEOUT_SECONDS", 12, 3, 60) * 1000,
    sshCommandMaxOutputBytes:
      integer("SSH_COMMAND_MAX_OUTPUT_BYTES", 262144, 4096, 1048576),
    probeTimeoutMs: integer("PROBE_TIMEOUT_SECONDS", 3, 1, 15) * 1000,
    probeConcurrency: integer("PROBE_CONCURRENCY", 20, 1, 100),
    maxProbeTargets: integer("MAX_PROBE_TARGETS", 250, 1, 1000),
    sshSessionMaxMs:
      integer("SSH_SESSION_MAX_SECONDS", 7200, 60, 14400) * 1000,
    webSocketHeartbeatMs:
      integer("WEBSOCKET_HEARTBEAT_SECONDS", 20, 10, 60) * 1000,
    webfigSessionTtlMs:
      integer("WEBFIG_SESSION_TTL_MINUTES", 30, 5, 120) * 60 * 1000,
    webfigUpstreamTimeoutMs:
      integer("WEBFIG_UPSTREAM_TIMEOUT_SECONDS", 30, 5, 120) * 1000,
    maxPendingWebfigSessions:
      integer("MAX_PENDING_WEBFIG_SESSIONS", 100, 1, 1000),
    maxActiveWebfigSessions:
      integer("MAX_ACTIVE_WEBFIG_SESSIONS", 20, 1, 200),
    maxPendingSessions: integer("MAX_PENDING_SESSIONS", 100, 1, 1000),
    maxActiveSessions: integer("MAX_ACTIVE_SESSIONS", 20, 1, 200),
    maxRequestBytes: 16 * 1024,
    maxWebSocketMessageBytes: 64 * 1024,
  };
}
