import http from "node:http";

export const WEBFIG_COOKIE = "c3_webfig_session";

/**
 * Faz parse seguro dos cookies recebidos pelo navegador.
 * Um cookie malformado não deve derrubar o proxy.
 */
function parseCookies(value = "") {
  const cookies = {};

  for (const rawPart of String(value).split(";")) {
    const part = rawPart.trim();
    if (!part) continue;

    const index = part.indexOf("=");

    const name = index < 0
      ? part
      : part.slice(0, index);

    const rawValue = index < 0
      ? ""
      : part.slice(index + 1);

    try {
      cookies[name] = decodeURIComponent(rawValue);
    } catch {
      cookies[name] = rawValue;
    }
  }

  return cookies;
}

/**
 * Remove somente o cookie interno do C3 Gateway antes de
 * encaminhar a requisição ao RouterOS.
 *
 * Os cookies pertencentes ao WebFig continuam sendo enviados.
 */
function withoutGatewayCookie(value = "") {
  return String(value)
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .filter((part) => {
      const name = part.split("=", 1)[0]?.trim();
      return name !== WEBFIG_COOKIE;
    })
    .join("; ");
}

/**
 * Cookie que mantém a sessão do gateway WebFig.
 *
 * SameSite=Lax é proposital:
 * a abertura do WebFig nasce de uma navegação top-level vinda
 * do C3 Protect e depois passa por redirect dentro de
 * webfig.c3protect.com.br.
 */
function sessionCookie(token, maxAgeSeconds) {
  return [
    `${WEBFIG_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    `Max-Age=${Math.max(1, Math.floor(maxAgeSeconds))}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
  ].join("; ");
}

function clearSessionCookie() {
  return [
    `${WEBFIG_COOKIE}=`,
    "Path=/",
    "Max-Age=0",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
  ].join("; ");
}

function writeHtml(response, status, title, message) {
  const body = `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width">
  <title>${title}</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #080a09;
      color: #f3f5f4;
      font: 16px system-ui, sans-serif;
    }

    .card {
      max-width: 32rem;
      margin: 2rem;
      padding: 2rem;
      border: 1px solid #ffffff18;
      border-radius: 14px;
      background: #101311;
    }

    h1 {
      font-size: 1.25rem;
      margin: 0 0 .75rem;
    }

    p {
      color: #ffffff99;
      line-height: 1.6;
      margin: 0;
    }
  </style>
</head>
<body>
  <main class="card">
    <h1>${title}</h1>
    <p>${message}</p>
  </main>
</body>
</html>`;

  response.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    pragma: "no-cache",
    expires: "0",
    "x-content-type-options": "nosniff",
  });

  response.end(body);
}

/**
 * Headers enviados do Gateway para o RouterOS.
 */
function upstreamHeaders(request, session, webfigHost) {
  const headers = { ...request.headers };

  const connectHost = session.connectHost ?? session.host;
  const upstreamAuthority = `${connectHost}:${session.port}`;

  headers.host = upstreamAuthority;

  headers.authorization = `Basic ${Buffer.from(
    `${session.username}:${session.password}`,
  ).toString("base64")}`;

  /*
   * Nunca enviar nosso cookie interno para o MikroTik.
   */
  headers.cookie = withoutGatewayCookie(
    String(headers.cookie ?? ""),
  );

  if (!headers.cookie) {
    delete headers.cookie;
  }

  /*
   * RouterOS pode conferir Origin/Referer.
   * Fazemos parecer que a requisição foi feita diretamente
   * para o WebFig local.
   */
  if (headers.origin) {
    headers.origin = `http://${upstreamAuthority}`;
  }

  if (headers.referer) {
    headers.referer = String(headers.referer).replace(
      `https://${webfigHost}`,
      `http://${upstreamAuthority}`,
    );
  }

  /*
   * Não deixar headers externos vazarem até o RouterOS.
   */
  delete headers["x-forwarded-host"];
  delete headers["x-forwarded-proto"];
  delete headers["x-forwarded-for"];
  delete headers["x-real-ip"];
  delete headers["cf-connecting-ip"];
  delete headers["cf-ray"];
  delete headers["cf-ipcountry"];

  return headers;
}

/**
 * Reescreve redirects absolutos do RouterOS.
 */
function rewriteLocation(location, session, publicBaseUrl) {
  if (!location) {
    return location;
  }

  const connectHost = session.connectHost ?? session.host;

  const possibleUpstreams = [
    `http://${connectHost}:${session.port}`,
    `https://${connectHost}:${session.port}`,
    `http://${session.host}:${session.port}`,
    `https://${session.host}:${session.port}`,
  ];

  let rewritten = String(location);

  for (const upstream of possibleUpstreams) {
    if (rewritten.startsWith(upstream)) {
      rewritten = rewritten.replace(upstream, publicBaseUrl);
      break;
    }
  }

  return rewritten;
}

/**
 * Remove atributos de domínio do RouterOS para que os cookies
 * pertençam ao webfig.c3protect.com.br.
 */
function rewriteSetCookie(value) {
  const cookies = Array.isArray(value)
    ? value
    : value
      ? [value]
      : [];

  return cookies.map((cookie) => {
    const parts = String(cookie)
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .filter((part) => !/^domain=/i.test(part))
      .filter((part) => !/^samesite=/i.test(part))
      .filter((part) => !/^secure$/i.test(part));

    parts.push("Secure");
    parts.push("SameSite=Lax");

    return parts.join("; ");
  });
}

export function isWebfigRequest(request, config) {
  const expected = new URL(
    config.webfigPublicBaseUrl,
  ).host.toLowerCase();

  return String(
    request.headers.host ?? "",
  ).toLowerCase() === expected;
}

/**
 * Proxy HTTP WebFig.
 */
export function handleWebfigRequest({
  request,
  response,
  config,
  store,
  audit,
}) {
  const url = new URL(
    request.url ?? "/",
    config.webfigPublicBaseUrl,
  );

  const openMatch = url.pathname.match(
    /^\/open\/([A-Za-z0-9_-]{20,})$/,
  );

  /*
   * Log seguro.
   *
   * Nunca registramos o valor dos cookies ou tokens.
   */
  audit("webfig.http_request", {
    method: request.method,
    path: openMatch ? "/open/[redacted]" : url.pathname,
    host: request.headers.host,
    hasCookie: Boolean(request.headers.cookie),
    cookieNames: String(request.headers.cookie ?? "")
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => part.split("=")[0])
      .filter(Boolean),
    userAgent: request.headers["user-agent"],
  });

  /*
   * =========================================================
   * ATIVAÇÃO DA SESSÃO
   * =========================================================
   *
   * /open/:token é descartável.
   *
   * Ele somente troca:
   *
   * access token -> session token
   *
   * Depois disso o navegador nunca mais precisa do token
   * presente na URL.
   */
  if (request.method === "GET" && openMatch) {
    try {
      const activated = store.activate(openMatch[1]);

      if (!activated) {
        audit("webfig.open_rejected", {
          reason: "expired_or_consumed",
        });

        writeHtml(
          response,
          401,
          "Link expirado",
          "Volte ao C3 Protect e abra uma nova sessão WebFig.",
        );

        return;
      }

      /*
       * O nome antigo webfig.connected era enganoso.
       *
       * Neste ponto ainda não houve conexão HTTP com o
       * RouterOS. Apenas ativamos a sessão.
       */
      audit("webfig.session_activated", {
        sessionId: activated.session.sessionId,
        deviceId: activated.session.deviceId,
        deviceName: activated.session.deviceName,
        actorEmail: activated.session.actorEmail,
        host: activated.session.host,
      });

      const maxAgeSeconds = Math.max(
        1,
        Math.floor(
          config.webfigSessionTtlMs / 1000,
        ),
      );

      const cookie = sessionCookie(
        activated.sessionToken,
        maxAgeSeconds,
      );

      audit("webfig.cookie_issued", {
        sessionId: activated.session.sessionId,
        cookieName: WEBFIG_COOKIE,
        maxAgeSeconds,
        redirectTo: `${config.webfigPublicBaseUrl}/`,
      });

      /*
       * 303 é intencional.
       *
       * Após consumir o token, forçamos uma nova navegação GET
       * para a raiz do domínio WebFig.
       *
       * Também usamos URL absoluta para eliminar qualquer
       * ambiguidade de host/proxy durante o redirect.
       */
      response.writeHead(303, {
        location: `${config.webfigPublicBaseUrl}/`,
        "set-cookie": cookie,
        "cache-control": "no-store, no-cache, must-revalidate",
        pragma: "no-cache",
        expires: "0",
      });

      response.end();
    } catch (error) {
      const overloaded =
        error?.message === "MAX_ACTIVE_WEBFIG_SESSIONS";

      audit("webfig.activation_failed", {
        code: error?.code ?? "unknown",
        message: error?.message ?? "unknown",
      });

      writeHtml(
        response,
        overloaded ? 503 : 500,
        overloaded
          ? "Limite de sessões"
          : "Falha ao abrir WebFig",
        overloaded
          ? "Finalize uma sessão WebFig antes de abrir outra."
          : "Não foi possível iniciar a sessão neste momento.",
      );
    }

    return;
  }

  /*
   * =========================================================
   * SESSÃO EXISTENTE
   * =========================================================
   */
  const cookies = parseCookies(
    String(request.headers.cookie ?? ""),
  );

  const token = cookies[WEBFIG_COOKIE];

  const session = token
    ? store.get(token)
    : null;

  audit("webfig.session_lookup", {
    path: url.pathname,
    hasSessionCookie: Boolean(token),
    sessionFound: Boolean(session),
    sessionId: session?.sessionId ?? null,
  });

  /*
   * =========================================================
   * ENCERRAMENTO EXPLÍCITO
   * =========================================================
   */
  if (
    request.method === "GET"
    && url.pathname === "/c3-session/close"
  ) {
    if (token) {
      store.revoke(token);
    }

    audit("webfig.session_closed", {
      sessionId: session?.sessionId ?? null,
      deviceId: session?.deviceId ?? null,
      actorEmail: session?.actorEmail ?? null,
      reason: "explicit_close",
    });

    response.writeHead(303, {
      location: config.webfigReturnUrl,
      "set-cookie": clearSessionCookie(),
      "cache-control": "no-store, no-cache, must-revalidate",
      pragma: "no-cache",
      expires: "0",
    });

    response.end();

    return;
  }

  /*
   * Sem cookie ou sessão já expirada.
   */
  if (!session) {
    /*
     * Limpa qualquer cookie antigo/inválido.
     */
    response.setHeader(
      "set-cookie",
      clearSessionCookie(),
    );

    writeHtml(
      response,
      401,
      "Sessão WebFig encerrada",
      "Volte ao C3 Protect para iniciar um novo acesso.",
    );

    return;
  }

  /*
   * =========================================================
   * PROXY HTTP -> ROUTEROS
   * =========================================================
   */
  const webfigHost = new URL(
    config.webfigPublicBaseUrl,
  ).host;

  const connectHost =
    session.connectHost ?? session.host;

  const proxyRequest = http.request(
    {
      host: connectHost,
      port: session.port,
      method: request.method,
      path: request.url,
      headers: upstreamHeaders(
        request,
        session,
        webfigHost,
      ),
      timeout: config.webfigUpstreamTimeoutMs,
    },
    (proxyResponse) => {
      const headers = {
        ...proxyResponse.headers,
      };

      headers["cache-control"] = "no-store";

      /*
       * Redirects do RouterOS.
       */
      if (headers.location) {
        headers.location = rewriteLocation(
          headers.location,
          session,
          config.webfigPublicBaseUrl,
        );
      } else {
        delete headers.location;
      }

      /*
       * Cookies do RouterOS.
       */
      const upstreamCookies =
        rewriteSetCookie(headers["set-cookie"]);

      if (upstreamCookies.length) {
        headers["set-cookie"] = upstreamCookies;
      } else {
        delete headers["set-cookie"];
      }

      /*
       * O WebFig pode enviar CSP apontando somente para seu
       * endereço local, impossibilitando o proxy externo.
       */
      delete headers["content-security-policy"];
      delete headers["content-security-policy-report-only"];

      audit("webfig.upstream_response", {
        sessionId: session.sessionId,
        deviceId: session.deviceId,
        method: request.method,
        path: url.pathname,
        statusCode: proxyResponse.statusCode ?? 502,
      });

      response.writeHead(
        proxyResponse.statusCode ?? 502,
        headers,
      );

      proxyResponse.pipe(response);
    },
  );

  proxyRequest.once("timeout", () => {
    proxyRequest.destroy(
      new Error("WEBFIG_TIMEOUT"),
    );
  });

  proxyRequest.once("error", (error) => {
    audit("webfig.proxy_failed", {
      sessionId: session.sessionId,
      deviceId: session.deviceId,
      host: session.host,
      connectHost,
      port: session.port,
      code: error.code ?? "unknown",
      message: error.message,
    });

    if (!response.headersSent) {
      writeHtml(
        response,
        502,
        "WebFig indisponível",
        "O Gateway não conseguiu alcançar o serviço WebFig desta RB.",
      );
    } else {
      response.destroy();
    }
  });

  request.pipe(proxyRequest);
}

/**
 * ===========================================================
 * WEBSOCKET / HTTP UPGRADE
 * ===========================================================
 */
export function handleWebfigUpgrade({
  request,
  socket,
  head,
  config,
  store,
  audit,
}) {
  const cookies = parseCookies(
    String(request.headers.cookie ?? ""),
  );

  const token = cookies[WEBFIG_COOKIE];

  const session = token
    ? store.get(token)
    : null;

  if (!session) {
    audit("webfig.websocket_rejected", {
      reason: token
        ? "session_not_found"
        : "missing_session_cookie",
    });

    socket.write(
      "HTTP/1.1 401 Unauthorized\r\n"
      + "Connection: close\r\n"
      + "Cache-Control: no-store\r\n"
      + "\r\n",
    );

    socket.destroy();
    return;
  }

  const webfigHost = new URL(
    config.webfigPublicBaseUrl,
  ).host;

  const connectHost =
    session.connectHost ?? session.host;

  const proxyRequest = http.request({
    host: connectHost,
    port: session.port,
    method: request.method,
    path: request.url,
    headers: upstreamHeaders(
      request,
      session,
      webfigHost,
    ),
  });

  proxyRequest.once(
    "upgrade",
    (
      proxyResponse,
      upstreamSocket,
      upstreamHead,
    ) => {
      const status =
        proxyResponse.statusCode ?? 101;

      const statusText =
        proxyResponse.statusMessage
        ?? "Switching Protocols";

      socket.write(
        `HTTP/1.1 ${status} ${statusText}\r\n`,
      );

      for (
        const [name, value]
        of Object.entries(proxyResponse.headers)
      ) {
        if (value === undefined) continue;

        socket.write(
          `${name}: ${
            Array.isArray(value)
              ? value.join(", ")
              : value
          }\r\n`,
        );
      }

      socket.write("\r\n");

      if (upstreamHead.length) {
        socket.write(upstreamHead);
      }

      if (head.length) {
        upstreamSocket.write(head);
      }

      audit("webfig.websocket_connected", {
        sessionId: session.sessionId,
        deviceId: session.deviceId,
        host: session.host,
      });

      upstreamSocket
        .pipe(socket)
        .pipe(upstreamSocket);

      const destroyBoth = () => {
        if (!socket.destroyed) {
          socket.destroy();
        }

        if (!upstreamSocket.destroyed) {
          upstreamSocket.destroy();
        }
      };

      socket.once("error", destroyBoth);
      upstreamSocket.once("error", destroyBoth);
    },
  );

  proxyRequest.once("error", (error) => {
    audit("webfig.websocket_failed", {
      sessionId: session.sessionId,
      deviceId: session.deviceId,
      host: session.host,
      connectHost,
      port: session.port,
      code: error.code ?? "unknown",
      message: error.message,
    });

    if (!socket.destroyed) {
      socket.destroy();
    }
  });

  proxyRequest.end();
}