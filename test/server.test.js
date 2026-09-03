import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import http from "node:http";
import { PassThrough } from "node:stream";
import WebSocket from "ws";

import { createGatewayServer } from "../src/server.js";
import { parseCidr } from "../src/security.js";
import { WEBFIG_COOKIE } from "../src/webfig-proxy.js";

const config = {
  port: 0,
  apiKey: "a".repeat(32),
  publicBaseUrl: "https://remote.c3protect.com.br",
  allowedOrigins: new Set(["https://c3-protect-remote.yan-nobrega.chatgpt.site"]),
  allowedCidrs: [parseCidr("172.18.18.0/24")],
  allowedPorts: new Set([22333]),
  allowedWebfigPorts: new Set([1080]),
  targetTranslations: [{
    source: parseCidr("172.18.18.0/24"),
    target: parseCidr("192.0.2.0/24"),
  }],
  tokenTtlMs: 60_000,
  sshConnectTimeoutMs: 10_000,
  sshCommandTimeoutMs: 2_000,
  sshCommandMaxOutputBytes: 256 * 1024,
  probeTimeoutMs: 1_000,
  probeConcurrency: 5,
  maxProbeTargets: 50,
  sshSessionMaxMs: 60_000,
  webSocketHeartbeatMs: 20_000,
  webfigPublicBaseUrl: "https://webfig.c3protect.com.br",
  webfigReturnUrl: "https://c3-protect-remote.yan-nobrega.chatgpt.site",
  webfigSessionTtlMs: 30 * 60_000,
  webfigUpstreamTimeoutMs: 5_000,
  maxPendingWebfigSessions: 10,
  maxActiveWebfigSessions: 5,
  maxPendingSessions: 10,
  maxActiveSessions: 5,
  maxRequestBytes: 16 * 1024,
  maxWebSocketMessageBytes: 64 * 1024,
};

async function withServer(callback, options = {}) {
  const gateway = createGatewayServer(config, {
    auditLogger: () => {},
    ...options,
  });
  await new Promise((resolve) => gateway.server.listen(0, "127.0.0.1", resolve));
  const address = gateway.server.address();
  try {
    await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    await gateway.close();
  }
}

function rawRequest(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const request = http.get(url, { headers }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.once("end", () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    request.once("error", reject);
  });
}

class FakeSshClient extends EventEmitter {
  connect(options) {
    this.connectOptions = options;
    queueMicrotask(() => this.emit("ready"));
  }

  shell(_options, callback) {
    const shell = new PassThrough();
    shell.stderr = new PassThrough();
    shell.setWindow = () => {};
    callback(null, shell);
  }

  exec(command, callback) {
    this.command = command;
    const stream = new PassThrough();
    stream.stderr = new PassThrough();
    callback(null, stream);
    queueMicrotask(() => stream.end([
      "===RESOURCE===",
      "uptime: 4d2h1m",
      "version: 7.21.1",
      "cpu-load: 7%",
      "board-name: RB5009UG+S+",
      "===HEALTH===",
      "cpu-temperature: 49C",
    ].join("\n")));
  }

  end() {}
}

test("health responde sem autenticação", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/health`);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).status, "ok");
  });
});

test("verifica a disponibilidade TCP de MikroTiks autorizados", async () => {
  await withServer(async (baseUrl) => {
    const port = Number(new URL(baseUrl).port);
    config.allowedCidrs.push(parseCidr("127.0.0.0/8"));
    config.allowedPorts.add(port);
    try {
      const response = await fetch(`${baseUrl}/v1/probes`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${config.apiKey}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          targets: [{ id: "rb-local", host: "127.0.0.1", port }],
        }),
      });
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.equal(body.results[0].id, "rb-local");
      assert.equal(body.results[0].online, true);
      assert.ok(body.results[0].latencyMs >= 1);
    } finally {
      config.allowedCidrs.pop();
      config.allowedPorts.delete(port);
    }
  });
});

test("cria uma sessão protegida e não devolve a senha", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/v1/sessions`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${config.apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        deviceId: "1",
        deviceName: "RB-REVITA",
        host: "172.18.18.209",
        port: 22333,
        username: "c3.remote",
        password: "senha-unica",
        actorEmail: "yan@c3support.com.br",
      }),
    });
    assert.equal(response.status, 201);
    const body = await response.json();
    assert.equal(body.websocketUrl, "wss://remote.c3protect.com.br/v1/terminal");
    assert.ok(body.token);
    assert.equal(JSON.stringify(body).includes("senha-unica"), false);
  });
});

test("executa somente diagnóstico RouterOS permitido e não devolve a senha", async () => {
  let sshClient;
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/v1/commands`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${config.apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        deviceId: "1",
        deviceName: "RB-REVITA",
        host: "172.18.18.209",
        port: 22333,
        username: "c3.remote",
        password: "senha-unica",
        actorEmail: "yan@c3support.com.br",
        commandId: "system-overview",
      }),
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.match(body.output, /RB5009/);
    assert.match(sshClient.command, /system resource print/);
    assert.equal(JSON.stringify(body).includes("senha-unica"), false);
    assert.equal(sshClient.connectOptions.host, "192.0.2.209");
  }, {
    createSshClient: () => {
      sshClient = new FakeSshClient();
      return sshClient;
    },
  });
});

test("rejeita comandos arbitrários", async () => {
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/v1/commands`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${config.apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        deviceId: "1",
        deviceName: "RB-REVITA",
        host: "172.18.18.209",
        port: 22333,
        username: "c3.remote",
        password: "senha-unica",
        actorEmail: "yan@c3support.com.br",
        commandId: "/user print",
      }),
    });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, "Comando não autorizado.");
  });
});

test("bloqueia API sem chave e IP fora das redes", async () => {
  await withServer(async (baseUrl) => {
    const unauthorized = await fetch(`${baseUrl}/v1/sessions`, { method: "POST" });
    assert.equal(unauthorized.status, 401);

    const forbiddenIp = await fetch(`${baseUrl}/v1/sessions`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${config.apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        deviceId: "1",
        deviceName: "RB-REVITA",
        host: "8.8.8.8",
        port: 22333,
        username: "c3.remote",
        password: "senha-unica",
        actorEmail: "yan@c3support.com.br",
      }),
    });
    assert.equal(forbiddenIp.status, 400);
    assert.equal((await forbiddenIp.json()).error, "IP SSH não autorizado.");
  });
});

test("cria sessão WebFig temporária e injeta a credencial somente no proxy", async () => {
  let receivedAuthorization = "";

  const upstream = http.createServer((request, response) => {
    receivedAuthorization = String(
      request.headers.authorization ?? "",
    );

    response.writeHead(200, {
      "content-type": "text/plain",
    });

    response.end("WEBFIG_OK");
  });

  await new Promise((resolve) => {
    upstream.listen(0, "127.0.0.1", resolve);
  });

  const upstreamPort = upstream.address().port;

  config.allowedCidrs.push(
    parseCidr("127.0.0.0/8"),
  );

  config.allowedWebfigPorts.add(upstreamPort);

  try {
    await withServer(async (baseUrl) => {
      /*
       * Cria a sessão temporária.
       */
      const createdResponse = await fetch(
        `${baseUrl}/v1/webfig-sessions`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${config.apiKey}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            deviceId: "1",
            deviceName: "RB-WEBFIG",
            host: "127.0.0.1",
            port: upstreamPort,
            username: "c3.remote",
            password: "senha-unica",
            actorEmail: "yan@c3support.com.br",
          }),
        },
      );

      assert.equal(
        createdResponse.status,
        201,
      );

      const created =
        await createdResponse.json();

      /*
       * A senha nunca pode aparecer na resposta da API.
       */
      assert.equal(
        JSON.stringify(created).includes(
          "senha-unica",
        ),
        false,
      );

      assert.ok(created.url);

      /*
       * Abre o link temporário /open/TOKEN.
       *
       * rawRequest é usado porque não queremos que o cliente
       * siga automaticamente o redirect.
       */
      const openResponse = await rawRequest(
        `${baseUrl}${new URL(created.url).pathname}`,
        {
          host: "webfig.c3protect.com.br",
        },
      );

      /*
       * Agora usamos 303 de forma intencional.
       */
      assert.equal(
        openResponse.status,
        303,
      );

      /*
       * O redirect deve apontar explicitamente para a URL
       * pública WebFig.
       */
      assert.equal(
        openResponse.headers.location,
        `${config.webfigPublicBaseUrl}/`,
      );

      /*
       * Deve existir o cookie da sessão.
       */
      const setCookies =
        openResponse.headers["set-cookie"];

      assert.ok(setCookies);
      assert.ok(setCookies.length > 0);

      const gatewayCookie =
        setCookies.find((value) =>
          value.startsWith(
            `${WEBFIG_COOKIE}=`,
          ),
        )
        ?? setCookies[0];

      /*
       * Verifica as propriedades de segurança do cookie.
       */
      assert.match(
        gatewayCookie,
        /HttpOnly/i,
      );

      assert.match(
        gatewayCookie,
        /Secure/i,
      );

      assert.match(
        gatewayCookie,
        /SameSite=Lax/i,
      );

      assert.match(
        gatewayCookie,
        /Path=\//i,
      );

      /*
       * Precisamos enviar somente name=value na requisição
       * seguinte, simulando o navegador.
       */
      const cookie =
        gatewayCookie.split(";")[0];

      assert.match(
        cookie,
        /^c3_webfig_session=/,
      );

      /*
       * Agora acessamos / com o cookie já estabelecido.
       */
      const proxyResponse =
        await rawRequest(
          `${baseUrl}/`,
          {
            host: "webfig.c3protect.com.br",
            cookie,
          },
        );

      assert.equal(
        proxyResponse.status,
        200,
      );

      assert.equal(
        proxyResponse.body,
        "WEBFIG_OK",
      );

      /*
       * A credencial deve existir somente entre Gateway
       * e RouterOS.
       */
      assert.equal(
        receivedAuthorization,
        `Basic ${Buffer.from(
          "c3.remote:senha-unica",
        ).toString("base64")}`,
      );
    });
  } finally {
    config.allowedCidrs.pop();

    config.allowedWebfigPorts.delete(
      upstreamPort,
    );

    await new Promise((resolve) => {
      upstream.close(resolve);
    });
  }
});

test("WebSocket consome o token e inicia a ponte SSH", async () => {
  let sshClient;
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/v1/sessions`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${config.apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        deviceId: "1",
        deviceName: "RB-REVITA",
        host: "172.18.18.209",
        port: 22333,
        username: "c3.remote",
        password: "senha-unica",
        actorEmail: "yan@c3support.com.br",
      }),
    });
    const session = await response.json();
    const socketUrl = baseUrl.replace(/^http/, "ws") + "/v1/terminal";

    await new Promise((resolve, reject) => {
      const socket = new WebSocket(socketUrl, ["c3-remote", session.token], {
        origin: "https://c3-protect-remote.yan-nobrega.chatgpt.site",
      });
      socket.once("error", reject);
      socket.on("message", (raw) => {
        const message = JSON.parse(raw.toString("utf8"));
        if (message.type === "status" && message.status === "connected") {
          assert.equal(sshClient.connectOptions.host, "192.0.2.209");
          assert.equal(sshClient.connectOptions.port, 22333);
          assert.equal(sshClient.connectOptions.username, "c3.remote");
          assert.equal(sshClient.connectOptions.password, "senha-unica");
          assert.equal(sshClient.connectOptions.keepaliveInterval, undefined);
          socket.send(JSON.stringify({ type: "heartbeat" }));
        } else if (message.type === "heartbeat") {
          socket.close();
          resolve();
        }
      });
    });
  }, {
    createSshClient: () => {
      sshClient = new FakeSshClient();
      return sshClient;
    },
  });
});
