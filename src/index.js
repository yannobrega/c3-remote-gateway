import { loadConfig } from "./config.js";
import { createGatewayServer } from "./server.js";

const config = loadConfig();
const gateway = createGatewayServer(config);

gateway.server.listen(config.port, "0.0.0.0", () => {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: "gateway.ready",
    port: config.port,
  }));
});

async function shutdown(signal) {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: "gateway.shutdown",
    signal,
  }));
  await gateway.close();
  process.exit(0);
}

process.once("SIGTERM", () => shutdown("SIGTERM"));
process.once("SIGINT", () => shutdown("SIGINT"));

