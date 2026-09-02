import test from "node:test";
import assert from "node:assert/strict";
import { SessionStore } from "../src/session-store.js";

test("token de sessão só pode ser consumido uma vez", () => {
  const store = new SessionStore({ ttlMs: 60_000, maxPending: 2 });
  const created = store.create({ host: "172.18.18.209" });
  assert.equal(store.consume(created.token).host, "172.18.18.209");
  assert.equal(store.consume(created.token), null);
});

test("limita sessões pendentes", () => {
  const store = new SessionStore({ ttlMs: 60_000, maxPending: 1 });
  store.create({ host: "172.18.18.209" });
  assert.throws(() => store.create({ host: "172.18.18.210" }), /MAX_PENDING/);
});

