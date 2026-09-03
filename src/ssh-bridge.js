import { Client as SshClient } from "ssh2";

function send(ws, message) {
  if (ws.readyState === 1) ws.send(JSON.stringify(message));
}

export function openSshBridge({
  ws,
  session,
  config,
  audit,
  onClose,
  createClient = () => new SshClient(),
}) {
  const client = createClient();
  let stream = null;
  let closed = false;
  let sshConnected = false;
  let lastSshError = null;

  const close = (code = 1000, reason = "Sessão encerrada") => {
    if (closed) return;
    closed = true;
    clearTimeout(maxDurationTimer);
    clearInterval(heartbeatTimer);
    try {
      stream?.end();
      client.end();
    } catch {
      // A conexão já pode ter sido encerrada pela outra ponta.
    }
    if (ws.readyState === 0 || ws.readyState === 1) {
      ws.close(code, reason.slice(0, 123));
    }
    onClose();
  };

  const maxDurationTimer = setTimeout(() => {
    send(ws, { type: "status", status: "expired", message: "Tempo máximo atingido." });
    audit("session.expired");
    close(4000, "Tempo máximo atingido");
  }, config.sshSessionMaxMs);
  maxDurationTimer.unref();

  // Mantém o WebSocket ativo através de proxies/CDNs sem depender do keepalive
  // SSH, que não é respondido de forma consistente por todas as versões RouterOS.
  const heartbeatTimer = setInterval(() => {
    if (ws.readyState === 1) ws.ping();
  }, config.webSocketHeartbeatMs);
  heartbeatTimer.unref();

  ws.on("message", (raw) => {
    if (raw.length > config.maxWebSocketMessageBytes) {
      close(1009, "Mensagem muito grande");
      return;
    }

    try {
      const message = JSON.parse(raw.toString("utf8"));
      if (message.type === "input" && typeof message.data === "string") {
        stream?.write(message.data);
      } else if (message.type === "heartbeat") {
        send(ws, { type: "heartbeat", timestamp: Date.now() });
      } else if (
        message.type === "resize" &&
        Number.isInteger(message.cols) &&
        Number.isInteger(message.rows) &&
        message.cols >= 20 &&
        message.cols <= 400 &&
        message.rows >= 5 &&
        message.rows <= 200
      ) {
        stream?.setWindow(message.rows, message.cols, 0, 0);
      }
    } catch {
      send(ws, { type: "error", message: "Mensagem de terminal inválida." });
    }
  });

  ws.once("close", (code, reason) => {
    audit("session.closed", {
      reason: "browser",
      code,
      message: reason?.toString("utf8") || null,
    });
    close();
  });
  ws.once("error", () => close(1011, "Erro no WebSocket"));

  client.on("ready", () => {
    sshConnected = true;
    audit("ssh.connected");
    client.shell(
      {
        term: "xterm-256color",
        cols: session.cols,
        rows: session.rows,
      },
      (error, shell) => {
        if (error) {
          send(ws, { type: "error", message: "Não foi possível abrir o terminal SSH." });
          audit("ssh.shell_failed");
          close(1011, "Falha ao abrir terminal");
          return;
        }

        stream = shell;
        send(ws, { type: "status", status: "connected" });
        shell.on("data", (data) =>
          send(ws, { type: "output", data: data.toString("utf8") }),
        );
        shell.stderr.on("data", (data) =>
          send(ws, { type: "output", data: data.toString("utf8") }),
        );
        shell.once("close", () => {
          audit("ssh.closed");
          close(1000, "SSH encerrado");
        });
        shell.once("error", () => close(1011, "Erro no terminal SSH"));
      },
    );
  });

  client.once("error", (error) => {
    lastSshError = {
      level: error.level ?? "unknown",
      code: error.code ?? "unknown",
      message: error.message ?? "unknown",
    };
    const isTimeout = error.level === "client-timeout" || error.code === "ETIMEDOUT";
    const isReset = error.code === "ECONNRESET" || error.code === "EPIPE";
    send(ws, {
      type: "error",
      message: error.level === "client-authentication"
        ? "Credencial SSH rejeitada pelo MikroTik."
        : isTimeout
          ? "O MikroTik parou de responder durante a sessão."
          : isReset
            ? "A conexão com o MikroTik foi interrompida pela rede."
            : sshConnected
              ? "A sessão SSH foi interrompida inesperadamente."
              : "Não foi possível conectar ao MikroTik.",
    });
    audit("ssh.failed", lastSshError);
    close(1011, "Falha na conexão SSH");
  });

  client.once("close", (hadError) => {
    audit("ssh.transport_closed", {
      connected: sshConnected,
      hadError: Boolean(hadError),
      lastError: lastSshError,
    });
    close(hadError ? 1011 : 1000, hadError ? "Transporte SSH interrompido" : "SSH encerrado");
  });

  const connectOptions = {
    host: session.connectHost ?? session.host,
    port: session.port,
    username: session.username,
    password: session.password,
    readyTimeout: config.sshConnectTimeoutMs,
  };

  if (session.hostKeySha256) {
    connectOptions.hostHash = "sha256";
    connectOptions.hostVerifier = (hash) => hash === session.hostKeySha256;
  }

  send(ws, { type: "status", status: "connecting" });
  audit("session.started");
  client.connect(connectOptions);

  return close;
}
