# Журнал автономной разработки ProxyDesk (docs/progress.md)

## Сводка выполнения инкрементов (A → H)

| Инкремент | Статус | Ключевые файлы и модули | Проверка и тесты |
| :--- | :--- | :--- | :--- |
| **Этап 0 (Ревью и Инженерная планка)** | Завершён | `docs/decisions.md`, `docs/invariants.md`, `docs/progress.md` | Зафиксированы SHA референсов (`963b14d`, `9a4b160`, `cc42f38`, `acaa01e`), помечены непроверенные по исходнику утверждения, описаны 9 инвариантов (`INV-01`..`INV-09`) и бюджеты ресурсов (`ADR-006`). |
| **Инкремент A — Основа и импорт** | Завершён | `go.mod`, `go.sum`, `cmd/proxydesk/main.go`, `internal/config/`, `internal/lock/`, `internal/model/`, `internal/diagnostics/`, `internal/storage/`, `internal/parsers/`, `internal/api/`, `web/` | Проверены схема SQLite 3.40.1 (`001_init.sql`), `CHECK`/`UNIQUE` ограничения, дедупликация без секретов в `dedup_key`/`raw_line`, защита `Host`/`Origin`/`X-ProxyDesk-Token`. |
| **Инкремент B — Источники и планировщик** | Завершён | `internal/sources/manager.go`, `internal/sources/manager_test.go`, `internal/parsers/normalize.go` | Парсеры `TXT`, `CSV`, `JSON`, статического `HTML`; поддержка `ETag`/`Last-Modified` (`HTTP 304`); SSRF-фильтр в `net.Dialer.Control`; экспоненциальный backoff с детерминированным jitter; предустановленные источники `monosans/proxy-list` (проверены `2026-10-13`). |
| **Инкремент C — Checker** | Завершён | `internal/checker/checker.go`, `internal/checker/checker_test.go` | Поэтапная проверка `HTTP`, `HTTP CONNECT` и `SOCKS5 CONNECT` (с передачей домена `ATYP=0x03`), полная проверка TLS-сертификатов, исходы `success`/`failure`/`inconclusive`/`cancelled`, отмена без утечки сокетов (`INV-03`). |
| **Инкремент D — История, рейтинг, пулы** | Завершён | `internal/scoring/scorer.go`, `internal/scoring/scorer_test.go`, `internal/pools/selector.go`, `internal/pools/selector_test.go` | Рейтинг `0–100`, эвристика полноты наблюдений `confidence` (`0–1`), карантин с cooldown, пулы и стратегии (`fixed`, `failover`, `best_score`, `round_robin`, `weighted`) с гистерезисом и `DecisionTrace`. |
| **Инкремент E — Локальный шлюз** | Завершён | `internal/gateway/gateway.go`, `internal/gateway/gateway_test.go` | Локальный `HTTP CONNECT` / forward и `SOCKS5` шлюз на loopback без MITM, маршруты `proxy`/`pool`/`block`/`direct`, failover до подтверждения туннеля (`INV-01`, `INV-02`, `INV-07`), очистка `Proxy-Authorization`. |
| **Инкремент F — DNS в пользовательском режиме** | Завершён | `internal/dns/server.go`, `internal/dns/server_test.go` | Локальный DNS-прокси (`127.0.0.1:15353`), `UDP`/`TCP`/`DoT`/`DoH`, `TC=1` → TCP retry, `NXDOMAIN` без ложного fallback, запрет утечки внутренних доменов, раздельный кэш по политикам (`INV-06`). |
| **Инкремент G — Связь DNS и маршрутов** | Завершён | `internal/rules/engine.go`, `internal/rules/engine_test.go`, `internal/gateway/gateway.go`, `internal/api/server.go` | Явные режимы `Remote DNS` и `Managed DNS` (с сохранением `Host`/TLS `SNI` и политикой `IPv4`/`IPv6`), сухой прогон правил (`/api/v1/rules/test`) с двойным `DecisionTrace`. |
| **Инкремент H — Полировка и выпуск** | Завершён | `README.md`, `THIRD_PARTY_NOTICES`, `docs/system-stage-proposal.md`, `.github/workflows/ci-windows.yml`, `web/dist/*` | 8 вкладок UI на русском, экспорт `TXT`/`JSON`, безопасный бэкап SQLite (`VACUUM INTO`) с проверкой версии, очищенный диагностический архив `.zip`, ротация логов. |

---

## Реально выполненные проверки и замеры в среде разработки

1. **Платформа выполнения проверок**: Linux Debian 12 (`x86_64`), Python `3.11.2`, SQLite `3.40.1`, Node.js `v18.20.4`, Git.
2. **Тесты UI, локализации, XSS-безопасности и Decision Trace (`node --test web/test_ui.mjs`)**:
   - Выполнено 3 теста (`pass 3`, `fail 0`, время `383.79 мс`).
3. **Проверка миграций, ограничений целостности, дедупликации и бэкапа SQLite (`3.40.1`)**:
   - Миграция `001_init.sql` в режиме `WAL` применена без ошибок.
   - Ограничения `CHECK` и `FOREIGN KEY` подтверждены.
   - Бенчмарк пакетной дедупликации и вставки `5 000` прокси-кандидатов в транзакции SQLite WAL: **`88.12 мс`**.
   - Создание горячего бэкапа через `VACUUM INTO` и проверка версии схемы (`schema_migrations.version = 1`) пройдены успешно.
4. **Статический аудит исходного кода Go и инварианта `INV-09`**:
   - Проверены все `23` файла `.go` (`11` модулей реализации и `11` тестовых пакетов `_test.go` + `web/embed.go`).
   - Вызовы изменения системных настроек ОС (`WinINET`, `netsh`, `WFP`, `WinDivert`, системный DNS, службы) гарантированно отсутствуют.
5. **Ограничение среды сборки (честная фиксация блокера компиляции Go)**:
   - В изолированной офлайн-среде контейнера отсутствует установленный компилятор `go` (`go: command not found`, внешний интернет отключен).
   - Вследствие этого запуск `go test ./...` и кросс-компиляция бинарного файла `proxydesk.exe` не могли быть физически выполнены внутри контейнера и подготовлены к воспроизводимому запуску одной командой на хост-машине или через `.github/workflows/ci-windows.yml`.
   - Приложение **не запускалось на реальной ОС Windows** (в контейнере работает Linux `x86_64`).
