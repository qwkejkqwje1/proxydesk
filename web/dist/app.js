// Скомпилированный клиентский бандл ProxyDesk (из web/src/i18n.ts и web/src/app.ts)
// Встраивается в бинарник через go:embed; не требует Node.js у пользователя.

const RU_STRINGS = {
  appTitle: "ProxyDesk",
  appSubtitle: "Портативный менеджер прокси, локального шлюза и пользовательского DNS (Windows 10/11 x64)",
  tabOverview: "Обзор",
  tabSources: "Источники",
  tabProxies: "Прокси",
  tabPools: "Пулы и выбор",
  tabGateway: "Локальный шлюз и маршруты",
  tabDNS: "DNS (пользовательский режим)",
  tabLogs: "Журнал и диагностика",
  tabSettings: "Настройки и бэкап",
  statusUnknown: "Не проверен (unknown)",
  statusChecking: "Проверяется (checking)",
  statusHealthy: "Рабочий (healthy)",
  statusDegraded: "Нестабилен (degraded)",
  statusQuarantined: "Карантин (quarantined)",
  confidenceTooltip: "Эвристика полноты наблюдений (учитывает число независимых циклов и временной охват; не является статистическим доверительным интервалом)",
  decisionTraceTitle: "Объяснение решения (Decision Trace — «Почему выбран этот маршрут/резолвер?»)",
  systemStageNotice: "Системный перехват (WinINET/PAC, драйвер TUN/Wintun, WFP process routing, Kill Switch и смена системного DNS Windows) выделен в отдельный привилегированный этап и не активируется в пользовательском портативном режиме."
};

function setSafeText(el, value) {
  if (!el) return;
  el.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
}

function getSessionToken() {
  if (typeof document === "undefined") return "";
  const meta = document.querySelector('meta[name="proxydesk-token"]');
  return meta ? (meta.getAttribute("content") || "") : "";
}

async function apiRequest(path, method = "GET", body = undefined) {
  const headers = { "X-ProxyDesk-Token": getSessionToken() };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const resp = await fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${errText}`);
  }
  return await resp.json();
}

function renderDecisionTrace(container, trace) {
  if (!container || !trace) return;
  container.replaceChildren();
  const card = document.createElement("div");
  card.className = "trace-card";

  const title = document.createElement("h4");
  setSafeText(title, `${RU_STRINGS.decisionTraceTitle} [${trace.component}]`);
  card.appendChild(title);

  const fields = [
    ["Совпавшее правило", trace.rule_matched],
    ["Режим разрешения DNS", trace.resolution_mode],
    ["Политика DNS", trace.dns_policy],
    ["Действие маршрута", trace.route_action],
    ["Рассмотрено кандидатов", trace.candidates_considered],
    ["Выбранный узел", trace.selected_candidate || "нет"],
    ["Причина выбора", trace.selection_reason],
    ["Причина переключения (Failover)", trace.failover_reason],
  ];

  const dl = document.createElement("dl");
  dl.className = "trace-grid";
  for (const [label, val] of fields) {
    if (val === undefined || val === "") continue;
    const dt = document.createElement("dt");
    setSafeText(dt, label);
    const dd = document.createElement("dd");
    setSafeText(dd, val);
    dl.appendChild(dt);
    dl.appendChild(dd);
  }
  card.appendChild(dl);

  if (Array.isArray(trace.excluded) && trace.excluded.length > 0) {
    const exHeader = document.createElement("div");
    exHeader.className = "trace-subhead";
    setSafeText(exHeader, `Исключённые кандидаты (${trace.excluded.length}):`);
    card.appendChild(exHeader);

    const ul = document.createElement("ul");
    ul.className = "trace-excluded-list";
    for (const ex of trace.excluded) {
      const li = document.createElement("li");
      setSafeText(li, `${ex.candidate} — ${ex.reason}`);
      ul.appendChild(li);
    }
    card.appendChild(ul);
  }

  container.appendChild(card);
}

let currentPage = 0;
const pageSize = 50;

async function refreshOverview() {
  const data = await apiRequest("/api/v1/overview");
  setSafeText(document.getElementById("stat-total"), data.proxies_total);
  setSafeText(document.getElementById("stat-healthy"), data.proxies_healthy);
  setSafeText(document.getElementById("stat-unknown"), data.proxies_unknown);
  setSafeText(document.getElementById("stat-quarantined"), `${data.proxies_degraded} / ${data.proxies_quarantined}`);
  setSafeText(document.getElementById("stat-sources"), data.sources_total);
  setSafeText(document.getElementById("budgets-viewer"), JSON.stringify(data.budgets, null, 2));
}

async function refreshProxies() {
  const search = document.getElementById("proxy-search")?.value || "";
  const proto = document.getElementById("proxy-filter-proto")?.value || "";
  const status = document.getElementById("proxy-filter-status")?.value || "";
  const offset = currentPage * pageSize;
  const q = new URLSearchParams({
    search,
    protocol: proto,
    status,
    limit: String(pageSize),
    offset: String(offset),
  });
  const data = await apiRequest(`/api/v1/proxies?${q.toString()}`);
  const tbody = document.getElementById("proxies-tbody");
  if (!tbody) return;
  tbody.replaceChildren();

  for (const item of data.items || []) {
    const tr = document.createElement("tr");
    const capConnect = item.capabilities?.connect?.state || "unknown";
    const capRDNS = item.capabilities?.remote_dns?.state || "unknown";
    const exitStr = item.rotating_exit_ip ? `${item.exit_ip} (ротация)` : (item.exit_ip || "—");
    const cells = [
      item.id,
      item.protocol.toUpperCase(),
      `${item.host}:${item.port}${item.has_auth ? " [auth]" : ""}`,
      item.status,
      item.cycles_count > 0 ? item.score.toFixed(1) : "— (не проверен)",
      item.cycles_count > 0 ? `${(item.confidence * 100).toFixed(0)}% (${item.cycles_count} цикл.)` : "0%",
      item.avg_total_ms !== null && item.avg_total_ms !== undefined ? `${item.avg_total_ms} мс` : "—",
      exitStr,
      `CONNECT: ${capConnect} | RDNS: ${capRDNS}`,
      item.sources_count,
    ];
    for (const c of cells) {
      const td = document.createElement("td");
      setSafeText(td, c);
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  setSafeText(document.getElementById("page-indicator"), `Страница ${currentPage + 1} (всего: ${data.total || 0})`);
}

async function refreshSources() {
  const data = await apiRequest("/api/v1/sources");
  const tbody = document.getElementById("sources-tbody");
  if (!tbody) return;
  tbody.replaceChildren();
  for (const s of data.items || []) {
    const tr = document.createElement("tr");
    const cols = [
      s.id,
      s.name,
      `${s.kind} / ${s.format}`,
      s.location,
      `${s.last_status}${s.last_error ? " (" + s.last_error + ")" : ""}`,
      `${s.total_unique} / ${s.total_errors}`,
      s.verified_date || "—",
    ];
    for (const c of cols) {
      const td = document.createElement("td");
      setSafeText(td, c);
      tr.appendChild(td);
    }
    const tdAct = document.createElement("td");
    const btnRun = document.createElement("button");
    btnRun.className = "btn-primary";
    setSafeText(btnRun, "Обновить");
    btnRun.addEventListener("click", async () => {
      await apiRequest("/api/v1/sources/refresh", "POST", { source_id: s.id });
      await refreshSources();
      await refreshProxies();
      await refreshOverview();
    });
    tdAct.appendChild(btnRun);
    tr.appendChild(tdAct);
    tbody.appendChild(tr);
  }
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  window.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("#main-tabs .tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll("#main-tabs .tab").forEach((b) => b.classList.remove("active"));
        document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        const tab = btn.getAttribute("data-tab");
        document.getElementById(`panel-${tab}`)?.classList.add("active");
      });
    });

    document.getElementById("btn-manual-import")?.addEventListener("click", async () => {
      const content = document.getElementById("manual-import-text")?.value || "";
      const default_protocol = document.getElementById("manual-import-proto")?.value || "http";
      const allow_private = Boolean(document.getElementById("manual-allow-private")?.checked);
      const res = await apiRequest("/api/v1/proxies/import", "POST", { content, default_protocol, allow_private });
      setSafeText(
        document.getElementById("manual-import-result"),
        `Импортировано уникальных: ${res.unique_count} (валидных строк: ${res.valid_count}, ошибок: ${res.error_count}). Статус: unknown.`
      );
      await refreshOverview();
      await refreshProxies();
    });

    refreshOverview().catch(() => {});
    refreshSources().catch(() => {});
    refreshProxies().catch(() => {});
  });
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { RU_STRINGS, setSafeText, renderDecisionTrace };
}
