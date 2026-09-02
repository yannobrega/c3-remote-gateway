import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import WebSocket from "ws";
import { createGatewayServer } from "../src/server.js";
import { parseCidr } from "../src/security.js";

const config = {
  port: 0,
  apiKey: "a".repeat(32),
  publicBaseUrl: "https://remote.c3protect.com.br",
  allowedOrigins: new Set(["https://c3-protect-remote.yan-nobrega.chatgpt.site"]),
  allowedCidrs: [parseCidr("172.18.18.0/24")],
  allowedPorts: new Set([22333]),
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
