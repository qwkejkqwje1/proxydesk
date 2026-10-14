// Вынесенный словарь строк интерфейса на русском языке для локализации (Increment 1 & H)
export interface I18nStrings {
  appTitle: string;
  appSubtitle: string;
  tabOverview: string;
  tabSources: string;
  tabProxies: string;
  tabPools: string;
  tabGateway: string;
  tabDNS: string;
  tabLogs: string;
  tabSettings: string;
  statusUnknown: string;
  statusChecking: string;
  statusHealthy: string;
  statusDegraded: string;
  statusQuarantined: string;
  confidenceTooltip: string;
  decisionTraceTitle: string;
  systemStageNotice: string;
}

export const RU_STRINGS: I18nStrings = {
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
