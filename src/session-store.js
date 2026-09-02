import { randomUUID } from "node:crypto";
import { hashToken, issueToken } from "./security.js";

export class SessionStore {
  constructor({ ttlMs, maxPending }) {
    this.ttlMs = ttlMs;
    this.maxPending = maxPending;
    this.sessions = new Map();
  }

  create(payload) {
    this.sweep();
    if (this.sessions.size >= this.maxPending) {
      throw new Error("MAX_PENDING_SESSIONS");
    }

    const token = issueToken();
    const sessionId = randomUUID();
    const expiresAt = Date.now() + this.ttlMs;
    this.sessions.set(hashToken(token), { ...payload, sessionId, expiresAt });
    return { token, sessionId, expiresAt };
  }

  consume(token) {
    const key = hashToken(token);
    const session = this.sessions.get(key);
    this.sessions.delete(key);
    if (!session || session.expiresAt <= Date.now()) return null;
    return session;
  }

  sweep() {
    const now = Date.now();
    for (const [key, session] of this.sessions) {
      if (session.expiresAt <= now) this.sessions.delete(key);
    }
  }

  get size() {
    this.sweep();
    return this.sessions.size;
  }

  clear() {
    this.sessions.clear();
  }
}

