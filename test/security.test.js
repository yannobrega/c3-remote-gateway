import test from "node:test";
import assert from "node:assert/strict";
import {
  isIpv4Allowed,
  issueToken,
  parseCidr,
  safeEqual,
  translateIpv4,
} from "../src/security.js";

test("valida IPv4 dentro das redes permitidas", () => {
  const cidrs = [parseCidr("172.18.18.0/24"), parseCidr("172.17.17.0/24")];
  assert.equal(isIpv4Allowed("172.18.18.209", cidrs), true);
  assert.equal(isIpv4Allowed("172.17.17.1", cidrs), true);
  assert.equal(isIpv4Allowed("10.0.0.1", cidrs), false);
  assert.equal(isIpv4Allowed("172.18.18.999", cidrs), false);
});

test("traduz o IP real para a rede virtual preservando o host", () => {
  const translations = [{
    source: parseCidr("172.18.18.0/24"),
    target: parseCidr("192.0.2.0/24"),
  }];
  assert.equal(translateIpv4("172.18.18.209", translations), "192.0.2.209");
  assert.equal(translateIpv4("172.17.17.10", translations), "172.17.17.10");
});

test("token possui entropia e comparação constante funciona", () => {
  const first = issueToken();
  const second = issueToken();
  assert.notEqual(first, second);
  assert.ok(first.length >= 40);
  assert.equal(safeEqual("segredo", "segredo"), true);
  assert.equal(safeEqual("segredo", "outro"), false);
});
