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

  const close = (code = 1000, reason = "Sessão encerrada") => {
    if (closed) return;
    closed = true;
    clearTimeout(maxDurationTimer);
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

  ws.on("message", (raw) => {
    if (raw.length > config.maxWebSocketMessageBytes) {
      close(1009, "Mensagem muito grande");
      return;
    }

    try {
      const message = JSON.parse(raw.toString("utf8"));
      if (message.type === "input" && typeof message.data === "string") {
        stream?.write(message.data);
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

  ws.once("close", () => {
    audit("session.closed", { reason: "browser" });
    close();
  });
  ws.once("error", () => close(1011, "Erro no WebSocket"));

  client.on("ready", () => {
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
    send(ws, {
      type: "error",
      message: error.level === "client-authentication"
        ? "Credencial SSH rejeitada pelo MikroTik."
        : "Não foi possível conectar ao MikroTik.",
    });
    audit("ssh.failed", { level: error.level ?? "unknown" });
    close(1011, "Falha na conexão SSH");
  });

  client.once("close", () => close(1000, "SSH encerrado"));

  const connectOptions = {
    host: session.host,
    port: session.port,
    username: session.username,
    password: session.password,
    readyTimeout: config.sshConnectTimeoutMs,
    keepaliveInterval: 10_000,
    keepaliveCountMax: 3,
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
