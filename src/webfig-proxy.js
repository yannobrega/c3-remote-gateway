import http from "node:http";

export const WEBFIG_COOKIE = "c3_webfig_session";

function parseCookies(value = "") {
  return Object.fromEntries(
    value.split(";").map((part) => part.trim()).filter(Boolean).map((part) => {
      const index = part.indexOf("=");
      return index < 0
        ? [part, ""]
        : [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
    }),
  );
}

function withoutGatewayCookie(value = "") {
  return value
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part && !part.startsWith(`${WEBFIG_COOKIE}=`))
    .join("; ");
}

function sessionCookie(token, maxAgeSeconds) {
  return `${WEBFIG_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Lax`;
}

function clearSessionCookie() {
  return `${WEBFIG_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

function writeHtml(response, status, title, message) {
  const body = `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${title}</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#080a09;color:#f3f5f4;font:16px system-ui,sans-serif}.card{max-width:32rem;margin:2rem;padding:2rem;border:1px solid #ffffff18;border-radius:14px;background:#101311}h1{font-size:1.25rem;margin:0 0 .75rem}p{color:#ffffff99;line-height:1.6;margin:0}</style></head><body><main class="card"><h1>${title}</h1><p>${message}</p></main></body></html>`;
  response.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

function upstreamHeaders(request, session, webfigHost) {
  const headers = { ...request.headers };
  const upstreamAuthority = `${session.connectHost ?? session.host}:${session.port}`;
  headers.host = upstreamAuthority;
  // RouterOS v7 WebFig authenticates through its encrypted /jsproxy flow.
  // Supplying HTTP Basic credentials here replaces headers used by that flow
  // and eventually makes RouterOS terminate the WebFig session (403/410).
  delete headers.authorization;
  headers.cookie = withoutGatewayCookie(String(headers.cookie ?? ""));
  if (!headers.cookie) delete headers.cookie;
  if (headers.origin) headers.origin = `http://${upstreamAuthority}`;
  if (headers.referer) {
    headers.referer = String(headers.referer).replace(`https://${webfigHost}`, `http://${upstreamAuthority}`);
  }
  delete headers["x-forwarded-host"];
  delete headers["x-forwarded-proto"];
  delete headers["x-forwarded-for"];
  return headers;
}

function rewriteLocation(location, session, publicBaseUrl) {
  if (!location) return location;
  const upstream = `http://${session.connectHost ?? session.host}:${session.port}`;
  return String(location).replace(upstream, publicBaseUrl);
}

function rewriteSetCookie(value) {
  const cookies = Array.isArray(value) ? value : value ? [value] : [];
  return cookies.map((cookie) => {
    const parts = String(cookie)
      .split(";")
      .map((part) => part.trim())
      .filter((part) => part && !/^domain=/i.test(part) && !/^samesite=/i.test(part) && !/^secure$/i.test(part));
    parts.push("Secure", "SameSite=Lax");
    return parts.join("; ");
  });
}

export function isWebfigRequest(request, config) {
  const expected = new URL(config.webfigPublicBaseUrl).host.toLowerCase();
  return String(request.headers.host ?? "").toLowerCase() === expected;
}

export function handleWebfigRequest({ request, response, config, store, audit }) {
  const url = new URL(request.url ?? "/", config.webfigPublicBaseUrl);
  const openMatch = url.pathname.match(/^\/open\/([A-Za-z0-9_-]{20,})$/);

  if (request.method === "GET" && openMatch) {
    try {
      const activated = store.activate(openMatch[1]);
      if (!activated) {
        writeHtml(response, 401, "Link expirado", "Volte ao C3 Protect e abra uma nova sessão WebFig.");
        return;
      }
      audit("webfig.connected", {
        sessionId: activated.session.sessionId,
        deviceId: activated.session.deviceId,
        deviceName: activated.session.deviceName,
        actorEmail: activated.session.actorEmail,
        host: activated.session.host,
      });
      audit("webfig.cookie_issued", {
        sessionId: activated.session.sessionId,
        cookieName: WEBFIG_COOKIE,
        maxAgeSeconds: Math.floor(config.webfigSessionTtlMs / 1000),
      });
      response.writeHead(302, {
        location: "/",
        "set-cookie": sessionCookie(
          activated.sessionToken,
          Math.floor(config.webfigSessionTtlMs / 1000),
        ),
        "cache-control": "no-store",
      });
      response.end();
    } catch (error) {
      const overloaded = error.message === "MAX_ACTIVE_WEBFIG_SESSIONS";
      writeHtml(
        response,
        overloaded ? 503 : 500,
        overloaded ? "Limite de sessões" : "Falha ao abrir WebFig",
        overloaded
          ? "Finalize uma sessão WebFig antes de abrir outra."
          : "Não foi possível iniciar a sessão neste momento.",
      );
    }
    return;
  }

  const cookies = parseCookies(String(request.headers.cookie ?? ""));
  const token = cookies[WEBFIG_COOKIE];
  const session = token ? store.get(token) : null;

  if (request.method === "GET" && url.pathname === "/c3-session/close") {
    if (token) store.revoke(token);
    response.writeHead(302, {
      location: config.webfigReturnUrl,
      "set-cookie": clearSessionCookie(),
      "cache-control": "no-store",
    });
    response.end();
    return;
  }

  if (!session) {
    if (url.pathname === "/") {
      audit("webfig.session_missing", {
        hasSessionCookie: Boolean(token),
      });
    }
    writeHtml(response, 401, "Sessão WebFig encerrada", "Volte ao C3 Protect para iniciar um novo acesso.");
    return;
  }

  const webfigHost = new URL(config.webfigPublicBaseUrl).host;
  const proxyRequest = http.request({
    host: session.connectHost ?? session.host,
    port: session.port,
    method: request.method,
    path: request.url,
    headers: upstreamHeaders(request, session, webfigHost),
    timeout: config.webfigUpstreamTimeoutMs,
  }, (proxyResponse) => {
    if ((proxyResponse.statusCode ?? 500) >= 400) {
      audit("webfig.upstream_rejected", {
        sessionId: session.sessionId,
        deviceId: session.deviceId,
        method: request.method,
        path: url.pathname,
        statusCode: proxyResponse.statusCode ?? 500,
      });
    }
    const headers = { ...proxyResponse.headers };
    headers["cache-control"] = "no-store, no-cache, must-revalidate, private";
    headers.pragma = "no-cache";
    headers.expires = "0";
    delete headers.etag;
    delete headers["last-modified"];
    if (headers.location) {
      headers.location = rewriteLocation(headers.location, session, config.webfigPublicBaseUrl);
    } else delete headers.location;
    const upstreamCookies = rewriteSetCookie(headers["set-cookie"]);
    if (upstreamCookies.length) headers["set-cookie"] = upstreamCookies;
    else delete headers["set-cookie"];
    delete headers["content-security-policy"];
    response.writeHead(proxyResponse.statusCode ?? 502, headers);
    proxyResponse.pipe(response);
  });

  proxyRequest.once("timeout", () => proxyRequest.destroy(new Error("WEBFIG_TIMEOUT")));
  proxyRequest.once("error", (error) => {
    audit("webfig.proxy_failed", {
      sessionId: session.sessionId,
      deviceId: session.deviceId,
      host: session.host,
      code: error.code ?? "unknown",
      message: error.message,
    });
    if (!response.headersSent) {
      writeHtml(response, 502, "WebFig indisponível", "O Gateway não conseguiu alcançar o serviço WebFig desta RB.");
    } else response.destroy();
  });
  request.pipe(proxyRequest);
}

export function handleWebfigUpgrade({ request, socket, head, config, store, audit }) {
  const cookies = parseCookies(String(request.headers.cookie ?? ""));
  const token = cookies[WEBFIG_COOKIE];
  const session = token ? store.get(token) : null;
  if (!session) {
    socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
    socket.destroy();
    return;
  }

  const webfigHost = new URL(config.webfigPublicBaseUrl).host;
  const proxyRequest = http.request({
    host: session.connectHost ?? session.host,
    port: session.port,
    method: request.method,
    path: request.url,
    headers: upstreamHeaders(request, session, webfigHost),
  });
  proxyRequest.once("upgrade", (proxyResponse, upstreamSocket, upstreamHead) => {
    const status = proxyResponse.statusCode ?? 101;
    const statusText = proxyResponse.statusMessage ?? "Switching Protocols";
    socket.write(`HTTP/1.1 ${status} ${statusText}\r\n`);
    for (const [name, value] of Object.entries(proxyResponse.headers)) {
      if (value !== undefined) socket.write(`${name}: ${Array.isArray(value) ? value.join(", ") : value}\r\n`);
    }
    socket.write("\r\n");
    if (upstreamHead.length) socket.write(upstreamHead);
    if (head.length) upstreamSocket.write(head);
    upstreamSocket.pipe(socket).pipe(upstreamSocket);
  });
  proxyRequest.once("error", (error) => {
    audit("webfig.websocket_failed", {
      sessionId: session.sessionId,
      deviceId: session.deviceId,
      code: error.code ?? "unknown",
    });
    socket.destroy();
  });
  proxyRequest.end();
}
