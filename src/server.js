import http from "node:http";
import net from "node:net";
import { WebSocketServer } from "ws";
import { SessionStore } from "./session-store.js";
import {
  getBearerToken,
  isIpv4Allowed,
  isOriginAllowed,
  safeEqual,
  translateIpv4,
} from "./security.js";
import { openSshBridge } from "./ssh-bridge.js";

const USERNAME_PATTERN = /^[a-zA-Z0-9._@-]{1,64}$/;
const HOST_KEY_PATTERN = /^[a-fA-F0-9]{64}$/;

export function probeTcp(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    let settled = false;
    const finish = (online, error = null) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({
        online,
        latencyMs: online ? Math.max(1, Date.now() - startedAt) : null,
        error,
      });
    };
    const socket = net.createConnection({ host, port });
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false, "timeout"));
    socket.once("error", (error) => finish(false, error.code ?? "unreachable"));
  });
}

async function mapWithConcurrency(items, concurrency, mapper) {
  const results = new Array(items.length);
  let nextIndex = 0;
  async function worker() {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await mapper(items[index], index);
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, () => worker()),
  );
  return results;
}

function json(response, status, body, extraHeaders = {}) {
  const data = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(data),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...extraHeaders,
  });
  response.end(data);
}

async function readJson(request, maxBytes) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBytes) throw new Error("BODY_TOO_LARGE");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function validateSession(payload, config) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return "Corpo da requisição inválido.";
  }

  const host = String(payload.host ?? "").trim();
  const port = Number(payload.port ?? 22333);
  const username = String(payload.username ?? "").trim();
  const password = String(payload.password ?? "");
  const actorEmail = String(payload.actorEmail ?? "").trim();
  const deviceId = String(payload.deviceId ?? "").trim();
  const deviceName = String(payload.deviceName ?? "").trim();
  const cols = Number(payload.cols ?? 120);
  const rows = Number(payload.rows ?? 32);
  const hostKeySha256 = payload.hostKeySha256
    ? String(payload.hostKeySha256).trim().toLowerCase()
    : null;

  if (!isIpv4Allowed(host, config.allowedCidrs)) return "IP SSH não autorizado.";
  if (!config.allowedPorts.has(port)) return "Porta SSH não autorizada.";
  if (!USERNAME_PATTERN.test(username)) return "Usuário SSH inválido.";
  if (!password || password.length > 256) return "Senha SSH inválida.";
  if (!deviceId || deviceId.length > 128) return "Dispositivo inválido.";
  if (!deviceName || deviceName.length > 128) return "Nome do dispositivo inválido.";
  if (!actorEmail || actorEmail.length > 254) return "Operador inválido.";
  if (!Number.isInteger(cols) || cols < 20 || cols > 400) return "Largura inválida.";
  if (!Number.isInteger(rows) || rows < 5 || rows > 200) return "Altura inválida.";
  if (hostKeySha256 && !HOST_KEY_PATTERN.test(hostKeySha256)) {
    return "Fingerprint SSH inválida.";
  }

  const connectHost = translateIpv4(host, config.targetTranslations ?? []);
  if (!connectHost) return "IP SSH inválido.";

  return {
    host,
    connectHost,
    port,
    username,
    password,
    actorEmail,
    deviceId,
    deviceName,
    cols,
    rows,
    hostKeySha256,
  };
}

export function createGatewayServer(config, options = {}) {
  const store = new SessionStore({
    ttlMs: config.tokenTtlMs,
    maxPending: config.maxPendingSessions,
  });
  const activeSessions = new Map();
  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: config.maxWebSocketMessageBytes,
    handleProtocols: (protocols) => protocols.has("c3-remote") ? "c3-remote" : false,
  });

  const audit = (event, details = {}) => {
    const record = { timestamp: new Date().toISOString(), event, ...details };
    (options.auditLogger ?? console.log)(JSON.stringify(record));
  };

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://gateway.local");

    if (request.method === "GET" && url.pathname === "/health") {
      json(response, 200, {
        status: "ok",
        pendingSessions: store.size,
        activeSessions: activeSessions.size,
      });
      return;
    }

    if (request.method === "POST" && url.pathname === "/v1/probes") {
      const bearer = getBearerToken(request);
      if (!bearer || !safeEqual(bearer, config.apiKey)) {
        json(response, 401, { error: "Não autorizado." }, {
          "www-authenticate": "Bearer",
        });
        return;
      }

      try {
        const payload = await readJson(request, config.maxRequestBytes);
        const targets = Array.isArray(payload?.targets) ? payload.targets : null;
        if (!targets || targets.length === 0 || targets.length > config.maxProbeTargets) {
          json(response, 400, { error: "Lista de MikroTiks inválida." });
          return;
        }

        const validated = [];
        for (const target of targets) {
          const id = String(target?.id ?? "").trim();
          const host = String(target?.host ?? "").trim();
          const port = Number(target?.port ?? 22333);
          const connectHost = translateIpv4(host, config.targetTranslations ?? []);
          if (
            !id ||
            id.length > 128 ||
            !isIpv4Allowed(host, config.allowedCidrs) ||
            !config.allowedPorts.has(port) ||
            !connectHost
          ) {
            json(response, 400, { error: "Alvo de verificação inválido." });
            return;
          }
          validated.push({ id, host, connectHost, port });
        }

        const checkedAt = new Date().toISOString();
        const results = await mapWithConcurrency(
          validated,
          config.probeConcurrency,
          async (target) => ({
            id: target.id,
            ...(await probeTcp(target.connectHost, target.port, config.probeTimeoutMs)),
          }),
        );
        json(response, 200, { checkedAt, results });
      } catch (error) {
        if (error instanceof SyntaxError) {
          json(response, 400, { error: "JSON inválido." });
        } else if (error.message === "BODY_TOO_LARGE") {
          json(response, 413, { error: "Requisição muito grande." });
        } else {
          audit("probe.error", { message: error.message });
          json(response, 500, { error: "Erro ao verificar MikroTiks." });
        }
      }
      return;
    }

    if (request.method === "POST" && url.pathname === "/v1/sessions") {
      const bearer = getBearerToken(request);
      if (!bearer || !safeEqual(bearer, config.apiKey)) {
        json(response, 401, { error: "Não autorizado." }, {
          "www-authenticate": "Bearer",
        });
        return;
      }

      try {
        const payload = await readJson(request, config.maxRequestBytes);
        const validated = validateSession(payload, config);
        if (typeof validated === "string") {
          json(response, 400, { error: validated });
          return;
        }

        const created = store.create(validated);
        const websocketBase = config.publicBaseUrl.replace(/^http/, "ws");
        audit("session.created", {
          sessionId: created.sessionId,
          deviceId: validated.deviceId,
          deviceName: validated.deviceName,
          actorEmail: validated.actorEmail,
          host: validated.host,
        });
        json(response, 201, {
          sessionId: created.sessionId,
          token: created.token,
          websocketUrl: `${websocketBase}/v1/terminal`,
          expiresAt: new Date(created.expiresAt).toISOString(),
        });
      } catch (error) {
        if (error instanceof SyntaxError) {
          json(response, 400, { error: "JSON inválido." });
        } else if (error.message === "BODY_TOO_LARGE") {
          json(response, 413, { error: "Requisição muito grande." });
        } else if (error.message === "MAX_PENDING_SESSIONS") {
          json(response, 503, { error: "Limite de sessões pendentes atingido." });
        } else {
          audit("api.error", { message: error.message });
          json(response, 500, { error: "Erro interno." });
        }
      }
      return;
    }

    json(response, 404, { error: "Rota não encontrada." });
  });

  server.on("upgrade", (request, socket, head) => {
    const url = new URL(request.url ?? "/", "http://gateway.local");
    const origin = request.headers.origin;
    if (
      url.pathname !== "/v1/terminal" ||
      !isOriginAllowed(origin, config.allowedOrigins)
    ) {
      socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return;
    }

    const protocols = String(request.headers["sec-websocket-protocol"] ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    const token = protocols[0] === "c3-remote" ? protocols[1] : null;
    const session = token ? store.consume(token) : null;
    if (!session) {
      socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return;
    }

    if (activeSessions.size >= config.maxActiveSessions) {
      socket.write("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return;
    }

    wss.handleUpgrade(request, socket, head, (ws) => {
      const auditSession = (event, extra = {}) => audit(event, {
        sessionId: session.sessionId,
        deviceId: session.deviceId,
        deviceName: session.deviceName,
        actorEmail: session.actorEmail,
        host: session.host,
        ...extra,
      });
      activeSessions.set(session.sessionId, () => {});
      try {
        const closeBridge = openSshBridge({
          ws,
          session,
          config,
          audit: auditSession,
          createClient: options.createSshClient,
          onClose: () => activeSessions.delete(session.sessionId),
        });
        if (activeSessions.has(session.sessionId)) {
          activeSessions.set(session.sessionId, closeBridge);
        }
      } catch {
        activeSessions.delete(session.sessionId);
        auditSession("ssh.failed", { level: "gateway" });
        ws.close(1011, "Falha ao iniciar SSH");
      }
    });
  });

  const sweepTimer = setInterval(() => store.sweep(), Math.min(config.tokenTtlMs, 30_000));
  sweepTimer.unref();

  async function close() {
    clearInterval(sweepTimer);
    for (const closeBridge of activeSessions.values()) {
      closeBridge(1001, "Gateway reiniciando");
    }
    store.clear();
    await new Promise((resolve) => server.close(resolve));
    wss.close();
  }

  return { server, close, store, activeSessions };
}
