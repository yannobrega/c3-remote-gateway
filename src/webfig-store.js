import { hashToken, issueToken } from "./security.js";
import { SessionStore } from "./session-store.js";

export class WebfigSessionStore {
  constructor({ tokenTtlMs, sessionTtlMs, maxPending, maxActive }) {
    this.pending = new SessionStore({ ttlMs: tokenTtlMs, maxPending });
    this.sessionTtlMs = sessionTtlMs;
    this.maxActive = maxActive;
    this.active = new Map();
  }

  create(payload) {
    return this.pending.create(payload);
  }

  activate(token) {
    this.sweep();
    const pending = this.pending.consume(token);
    if (!pending) return null;
    if (this.active.size >= this.maxActive) {
      throw new Error("MAX_ACTIVE_WEBFIG_SESSIONS");
    }

    const sessionToken = issueToken();
    const expiresAt = Date.now() + this.sessionTtlMs;
    const session = { ...pending, expiresAt };
    this.active.set(hashToken(sessionToken), session);
    return { sessionToken, session, expiresAt };
  }

  get(sessionToken) {
    this.sweep();
    const session = this.active.get(hashToken(sessionToken));
    return session && session.expiresAt > Date.now() ? session : null;
  }

  revoke(sessionToken) {
    return this.active.delete(hashToken(sessionToken));
  }

  sweep() {
    this.pending.sweep();
    const now = Date.now();
    for (const [key, session] of this.active) {
      if (session.expiresAt <= now) this.active.delete(key);
    }
  }

  clear() {
    this.pending.clear();
    this.active.clear();
  }

  get pendingSize() {
    return this.pending.size;
  }

  get activeSize() {
    this.sweep();
    return this.active.size;
  }
}
