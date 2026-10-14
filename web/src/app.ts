import { RU_STRINGS } from "./i18n";

export interface DecisionTrace {
  timestamp: string;
  component: string;
  rule_matched: string;
  dns_policy?: string;
  resolution_mode?: string;
  route_action?: string;
  candidates_considered: number;
  excluded?: Array<{ candidate: string; reason: string }>;
  selected_candidate?: string;
  selection_reason: string;
  failover_reason?: string;
}

export interface ProxyItem {
  id: number;
  protocol: string;
  host: string;
  port: number;
  has_auth: boolean;
  status: string;
  score: number;
  confidence: number;
  cycles_count: number;
  success_rate: number;
  avg_total_ms: number | null;
  exit_ip: string;
  rotating_exit_ip: boolean;
  capabilities: Record<string, { state: string; verified_at?: string; detail?: string }>;
  score_breakdown: Record<string, unknown>;
  last_healthy_at: string;
  sources_count: number;
}

// Безопасное создание текстового узла: исключает XSS при отображении любых строк из внешних списков прокси
export function setSafeText(el: HTMLElement, value: string | number | null | undefined): void {
  el.textContent = value === null || value === undefined ? "—" : String(value);
}

export function getSessionToken(): string {
  const meta = document.querySelector('meta[name="proxydesk-token"]');
  return meta ? (meta.getAttribute("content") || "") : "";
}

export async function apiRequest<T>(path: string, method: string = "GET", body?: unknown): Promise<T> {
  const headers: Record<string, string> = {
    "X-ProxyDesk-Token": getSessionToken(),
  };
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
  return (await resp.json()) as T;
}

export function renderDecisionTrace(container: HTMLElement, trace: DecisionTrace): void {
  container.replaceChildren();
  const card = document.createElement("div");
  card.className = "trace-card";

  const title = document.createElement("h4");
  setSafeText(title, `${RU_STRINGS.decisionTraceTitle} [${trace.component}]`);
  card.appendChild(title);

  const fields: Array<[string, string | number | undefined]> = [
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

  if (trace.excluded && trace.excluded.length > 0) {
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
