import { Client as SshClient } from "ssh2";

export const ROUTEROS_COMMANDS = Object.freeze({
  "system-overview":
    ':put "===RESOURCE==="; /system resource print without-paging; :put "===HEALTH==="; /system health print without-paging',
  interfaces: "/interface print detail without-paging",
  "ip-addresses": "/ip address print detail without-paging",
  routes: "/ip route print detail without-paging",
  "dhcp-leases": "/ip dhcp-server lease print detail without-paging",
  neighbors: "/ip neighbor print detail without-paging",
  firewall: "/ip firewall filter print stats without-paging",
  sstp: "/interface sstp-client print detail without-paging",
  logs: '/log print without-paging where topics~"critical|error|warning"',
  connections: "/ip firewall connection print count-only",
});

export function runSshCommand({
  target,
  commandId,
  config,
  createClient = () => new SshClient(),
}) {
  const command = ROUTEROS_COMMANDS[commandId];
  if (!command) throw new Error("COMMAND_NOT_ALLOWED");

  return new Promise((resolve, reject) => {
    const client = createClient();
    const chunks = [];
    let outputBytes = 0;
    let settled = false;

    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        client.end();
      } catch {
        // A conexão pode já ter sido encerrada pelo MikroTik.
      }
      if (error) reject(error);
      else resolve(result);
    };

    const timer = setTimeout(
      () => finish(new Error("COMMAND_TIMEOUT")),
      config.sshCommandTimeoutMs,
    );
    timer.unref();

    client.once("ready", () => {
      client.exec(command, (error, stream) => {
        if (error) {
          finish(new Error("COMMAND_EXEC_FAILED"));
          return;
        }

        const append = (data) => {
          if (settled) return;
          const buffer = Buffer.from(data);
          outputBytes += buffer.length;
          if (outputBytes > config.sshCommandMaxOutputBytes) {
            try {
              stream.close();
            } catch {
              // O stream pode já estar fechado.
            }
            finish(new Error("COMMAND_OUTPUT_TOO_LARGE"));
            return;
          }
          chunks.push(buffer);
        };

        stream.on("data", append);
        stream.stderr?.on("data", append);
        stream.once("error", () => finish(new Error("COMMAND_STREAM_FAILED")));
        stream.once("close", (code) => {
          finish(null, {
            output: Buffer.concat(chunks).toString("utf8"),
            exitCode: Number.isInteger(code) ? code : null,
          });
        });
      });
    });

    client.once("error", (error) => {
      const wrapped = new Error(
        error.level === "client-authentication"
          ? "SSH_AUTH_FAILED"
          : "SSH_CONNECT_FAILED",
      );
      wrapped.level = error.level;
      finish(wrapped);
    });
    client.once("close", () => {
      if (!settled) finish(new Error("SSH_CLOSED_EARLY"));
    });

    const connectOptions = {
      host: target.connectHost ?? target.host,
      port: target.port,
      username: target.username,
      password: target.password,
      readyTimeout: config.sshConnectTimeoutMs,
      keepaliveInterval: 10_000,
      keepaliveCountMax: 2,
    };
    if (target.hostKeySha256) {
      connectOptions.hostHash = "sha256";
      connectOptions.hostVerifier = (hash) => hash === target.hostKeySha256;
    }
    client.connect(connectOptions);
  });
}
