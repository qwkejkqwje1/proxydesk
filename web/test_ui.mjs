import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { RU_STRINGS, setSafeText, renderDecisionTrace } = require("./dist/app.js");

test("RU_STRINGS contains required Russian localization keys and heuristic confidence notice", () => {
  assert.equal(RU_STRINGS.appTitle, "ProxyDesk");
  assert.ok(RU_STRINGS.confidenceTooltip.includes("Эвристика полноты наблюдений"));
  assert.ok(RU_STRINGS.confidenceTooltip.includes("не является статистическим доверительным интервалом"));
  assert.ok(RU_STRINGS.systemStageNotice.includes("WinINET/PAC"));
});

test("setSafeText assigns textContent and never interprets HTML/XSS tags", () => {
  const fakeElement = { textContent: "", innerHTML: "" };
  const malicious = '<img src=x onerror="alert(1)">socks5://198.51.100.1:1080';
  setSafeText(fakeElement, malicious);
  assert.equal(fakeElement.textContent, malicious);
  assert.equal(fakeElement.innerHTML, "");
});

test("renderDecisionTrace builds structured explanation of matched rule, DNS policy, and excluded candidates", () => {
  const makeEl = (tag) => ({
    tag,
    className: "",
    textContent: "",
    children: [],
    appendChild(child) { this.children.push(child); },
    replaceChildren() { this.children = []; }
  });
  globalThis.document = { createElement: makeEl };

  const container = makeEl("div");
  renderDecisionTrace(container, {
    timestamp: "2026-10-13T18:00:00Z",
    component: "pool",
    rule_matched: "pool:Reliable HTTPS",
    dns_policy: "remote_dns",
    route_action: "pool",
    candidates_considered: 3,
    excluded: [
      { candidate: "http://198.51.100.1:8080", reason: "capability connect is unknown" }
    ],
    selected_candidate: "socks5://203.0.113.5:1080",
    selection_reason: "selected highest-ranked eligible candidate (score=88.4)"
  });

  assert.equal(container.children.length, 1);
  const card = container.children[0];
  assert.equal(card.className, "trace-card");
  assert.ok(card.children[0].textContent.includes("[pool]"));
});
