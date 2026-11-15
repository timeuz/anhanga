# Anhangá

**Edge, TLS and latency auditor for SRE and DevSecOps teams.**

[Português (Brasil)](README.pt-BR.md)

Anhangá is a self-hosted, asynchronous diagnostics and monitoring tool for web endpoints. A bare `HTTP 200` rarely tells the whole story, so it inspects the full connection path: DNS, TCP and TLS handshakes, time to first byte, redirect chains, certificate and revocation status, protocol and cipher support, and the security posture of the response headers. It runs as a web dashboard with continuous monitoring, as a CLI for CI/CD quality gates, and as a Prometheus target compatible with `blackbox_exporter` dashboards.

**Status:** pre-release (0.2.x). The test suite is extensive, but the project has not yet had a long soak run or broad real-world use. See [Known limitations](#known-limitations).

**Scope:** Anhangá is designed to be run by each operator on their own infrastructure. It is not a multi-tenant or public scanning service: it has one shared API key, no per-user quotas, and no isolation between users. It is also not a penetration test or a replacement for a full TLS assessment tool (see [Validation](#validation)).

## Contents

- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Command-line interface](#command-line-interface)
- [HTTP API](#http-api)
- [Prometheus integration](#prometheus-integration)
- [Alerting](#alerting)
- [Persistence](#persistence)
- [Security model](#security-model)
- [How to read the results](#how-to-read-the-results)
- [Validation](#validation)
- [Known limitations](#known-limitations)
- [Development](#development)
- [License](#license)

## Features

**Latency diagnostics**
- Per-phase (non-cumulative) timings for DNS, TCP, TLS, TTFB and transfer, with start and end offsets and automatic identification of the dominant phase.
- Multi-sample probing (up to 20 samples): P50, P95, P99, mean, min/max and jitter, plus cold versus reused-connection comparison. P95 is only reported with at least 20 samples and P99 with at least 100 (see [percentiles](#percentiles)).
- Redirect chain tracing (301, 302, 303, 307, 308) with status, resolved IP and latency per hop.

**TLS inspection**
- Certificate validity, days remaining, issuer, subject, serial number, SHA-256 fingerprint, SANs and the X.509 chain.
- Negotiated protocol and cipher, and OCSP stapling status.
- Active revocation checking (OCSP with CRL fallback, signatures verified).
- Protocol and cipher enumeration (TLS 1.0 to 1.3) with findings for legacy protocols, weak ciphers and missing forward secrecy.

**Edge security audit**
- Security grade from `A+` to `F` based on HSTS, Content-Security-Policy (with a strength analysis), Permissions-Policy, X-Content-Type-Options, Referrer-Policy, cookie flags, CORS policy and technology version leakage.
- COOP, COEP and CORP are reported as informational and do not affect the grade.
- Remediation runbook with copy-paste snippets for Nginx, Apache, Caddy, Traefik and Kubernetes Ingress, and a grade projection simulator.

**Monitoring and alerting**
- Continuous background probing of a configured target list, with sparklines, uptime and incident history in the dashboard.
- Stateful alerts (anti-flapping, deduplication, reminders, recovery) delivered to Slack, Microsoft Teams or Telegram, with a persistent retry outbox.

**Safety**
- Built-in SSRF and DNS rebinding protection; the connection is pinned to the validated IP.
- Fail-closed API authentication and a rate limiter.

## Installation

Requires Python 3.11 or later and the `openssl` binary (used for the certificate chain, OCSP stapling and revocation checks; without it those fields are reported as "not verified").

```bash
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e .
```

With plain `pip`: `python -m venv .venv && . .venv/bin/activate && pip install -e .`

**Docker**

```bash
docker build -t anhanga .
docker run -d -p 7890:7890 --env-file .env -v "$PWD/data:/data" anhanga
```

Put `targets.yaml` in `data/` (the directory must be writable by uid 10001). The container runs as an unprivileged user, has a `HEALTHCHECK`, and refuses to start without `ANHANGA_API_KEY` because it listens on a non-loopback address.

## Quick start

```bash
anhanga serve                  # http://127.0.0.1:7890
```

- Dashboard (Portuguese and English): `http://127.0.0.1:7890`
- Health check: `GET /healthz`
- OpenAPI documentation: disabled by default; set `ANHANGA_DOCS=1` to enable `/docs`.

The dashboard runs on-demand scans, simulates remediation, compares re-scans, and exports a shareable analysis link, JSON and Markdown. It auto-refreshes every 15 seconds, filters and sorts targets by status, and shows 24-hour uptime and recent incidents.

`anhanga serve` always runs a single worker. Each worker would run its own monitoring loop and duplicate alerts, so do not use `uvicorn --workers` or `WEB_CONCURRENCY` greater than 1.

## Configuration

### `targets.yaml`

Anhangá looks for `targets.yaml` in the working directory, or at the path in `ANHANGA_CONFIG`. If `ANHANGA_CONFIG` is set and the file does not exist, that is an error and no other file is used. Start from the example:

```bash
cp targets.example.yaml targets.yaml
```

```yaml
interval_seconds: 30      # 5 to 86400; counted from the start of each cycle
samples: 3                # 1 to 20 samples per cycle
allow_private: false      # true only for internal or lab networks

slo:                      # optional global SLOs; each target may override
  max_ttfb: 800ms
  max_total: 2s
min_grade: C              # alert when the security grade falls below this

targets:
  - https://cloudflare.com
  - url: https://api.example.com/health
    samples: 5
    slo: { max_ttfb: 300ms }
    min_grade: B

alerting:
  failure_threshold: 2    # consecutive bad cycles before alerting
  recovery_threshold: 1
  cooldown_seconds: 3600  # reminder interval; 0 disables reminders
  notify_recovery: true

storage:
  enabled: true
  path: anhanga.db        # ANHANGA_DB_PATH overrides
  retention_days: 14

webhooks:
  - url: "${SLACK_WEBHOOK_URL}"   # ${VAR} expands environment variables
    provider: slack
  - url: "https://api.telegram.org/bot<TOKEN>/sendMessage"
    provider: telegram
    telegram_chat_id: "-1001234567890"
```

The file is validated on load: errors are logged and invalid entries are dropped instead of stopping the server. It is hot-reloaded when it changes; if the new file is unreadable or invalid YAML, the reload is rejected and the previous configuration stays in effect. Booleans are strict (`true/false`, `yes/no`, `on/off`, `1/0`); any other value is an error and falls back to the safe default. Targets are deduplicated by normalized URL (`example.com`, `https://example.com` and `HTTPS://EXAMPLE.COM` are the same target). Internationalized hostnames are accepted and converted to Punycode (IDNA 2008).

### Targets added from the dashboard

The "Add target" field in the dashboard stores permanent targets in SQLite (up to 50) without editing `targets.yaml`. A "Remove" button, with a two-click confirmation, appears only on those cards.

- Targets from `targets.yaml` stay in the file, cannot be removed from the UI, and win on duplicates.
- Dashboard targets never use `allow_private` (that is an operator decision, in the YAML only). Loopback and private addresses are rejected with 403 and are not stored.
- They inherit the top-level `slo` and `min_grade`.
- Endpoints: `GET`, `POST` and `DELETE /api/v1/targets/managed`. They require the API key like the rest of `/api/`, and the POST body must be JSON.
- The database becomes part of your state: back it up (see [Persistence](#persistence)).

### Environment variables

| Variable | Purpose |
| --- | --- |
| `ANHANGA_API_KEY` | API key. Required to listen outside loopback or behind a reverse proxy. |
| `ANHANGA_CONFIG` | Path to `targets.yaml`. |
| `ANHANGA_DB_PATH` | SQLite database path (overrides `storage.path`). |
| `ANHANGA_ENV_FILE` | Path of the `.env` file read by the server (default `./.env`). |
| `ANHANGA_ALLOW_PRIVATE` | `1` allows private addresses on the HTTP scan routes (operator decision). |
| `ANHANGA_REVOCATION_CHECK` | `0` disables OCSP/CRL checks. |
| `ANHANGA_REVOCATION_ALLOW_PRIVATE` | `1` lets OCSP/CRL URLs resolve to private addresses (internal PKI). |
| `ANHANGA_TLS_ENUM` | `0` disables protocol and cipher enumeration. |
| `ANHANGA_RATE_LIMIT_PER_MIN` | Per-IP rate limit (default 30; `samples=N` costs N). |
| `ANHANGA_TRUSTED_PROXIES` | Proxy IPs whose `X-Forwarded-For` is honored (empty by default). |
| `ANHANGA_SENSITIVE_COOKIE_REGEX` | Overrides which cookie names require `HttpOnly`. |
| `ANHANGA_DOCS` | `1` enables `/docs`, `/redoc` and `/openapi.json`. |
| `ANHANGA_PROBE_ORIGIN` | Label for the probe's vantage point in results. |

The `.env` file is read only by the server entrypoints (`anhanga serve`, `uvicorn anhanga.main:app`), never by `anhanga check`. Variables already set in the environment take precedence.

## Command-line interface

```bash
anhanga serve [--host 127.0.0.1] [--port 7890]
anhanga check <url> [gates and options]
anhanga keygen [--force]
anhanga backup <destination.db> [--force]
```

### `anhanga check`

Use it in CI/CD (GitHub Actions, GitLab CI, Jenkins, Azure DevOps) to gate a deployment on performance and security.

```bash
# Minimum grade B, TTFB under 500 ms, 3 samples
anhanga check https://example.com --min-grade B --max-ttfb 500ms --samples 3

# Also bound total latency
anhanga check https://api.example.com --min-grade A --max-ttfb 300ms --max-total 1.5s

# JSON for scripts, SARIF for GitHub Code Scanning
anhanga check https://example.com --min-grade B --format json --output report.json
anhanga check https://example.com --min-grade A --format sarif --output anhanga.sarif

# Notify a webhook when a gate fails
anhanga check https://example.com --min-grade B \
  --webhook-url "https://hooks.slack.com/services/T000/B000/X000" --webhook-provider slack
```

Options: `--min-grade`, `--max-ttfb`, `--max-total`, `--samples/-n`, `--timeout/-t`, `--allow-private`, `--allow-invalid-cert`, `--format/-f {text,json,sarif}`, `--output/-o`, `--webhook-url`, `--webhook-provider {auto,slack,teams,telegram}`, `--telegram-chat-id`.

`--max-ttfb` uses the median of the samples and `--max-total` the headline latency, the same functions the monitor uses for its SLOs.

| Exit code | Meaning |
| :---: | --- |
| `0` | All checks passed. |
| `1` | Target offline, invalid TLS certificate (unless `--allow-invalid-cert`), TTFB or total latency above the limit, or a content assertion failed. |
| `2` | Security grade below `--min-grade`. |
| `3` | DNS error, SSRF block, invalid target, or invalid arguments or configuration. |

On a single-run `check`, the TLS protocol and cipher block may be reported as "not evaluated" because enumeration finishes in the background; it is never reported as "no protocols".

### `keygen` and `backup`

`anhanga keygen` generates 256 random bits and writes `ANHANGA_API_KEY` to `./.env` with mode `0600`. It does not overwrite an existing key without `--force`.

`anhanga backup` takes a consistent copy of the database using the SQLite backup API. It can run while the server is up, writes with mode `0600`, expands `~`, and refuses to overwrite without `--force`. Schedule it from the host's cron.

## HTTP API

All routes under `/api/`, plus `/probe` and `/metrics`, require the API key. `/healthz` and the dashboard HTML are open; cached data is embedded in the page only for authorized clients.

| Route | Description |
| --- | --- |
| `GET /api/v1/scan?url=&samples=&timeout=` | On-demand diagnostic of any URL (the dashboard's scan button). Supports content assertions. Not stored. |
| `GET /api/v1/targets` | Last known state of all monitored targets. |
| `GET/POST/DELETE /api/v1/targets/managed` | Targets added from the dashboard. |
| `GET /api/v1/history?target=&hours=24&max_points=300` | Aggregated series: checks, up/degraded/down and mean/min/max latency per bucket. |
| `GET /api/v1/uptime[?target=]` | `uptime_pct` (health up) and `availability_pct` (HTTP answered) over 24 h, 7 d and 30 d, with real data coverage. |
| `GET /api/v1/incidents[?target=&open_only=true&limit=]` | Open and closed incidents with duration. |
| `POST /api/v1/webhooks/notify` | Sends a server-generated alert to a webhook declared in `targets.yaml`. |
| `GET /probe?target=&samples=` | On-demand probe in `blackbox_exporter` multi-target style. |
| `GET /metrics` | Prometheus metrics for monitored targets. |

Failures where the target did not answer return structured errors: `400` invalid URL, `403` SSRF block, `502` DNS, connection or TLS failure, `504` timeout, with `{"detail": {"error_code", "message", "target_url"}}`. Findings about a target that did answer (5xx, failed assertion, invalid TLS) remain `200`.

## Prometheus integration

Durations are exported in seconds. Besides the extended `anhanga_probe_*` series, the standard `blackbox_exporter` series are exported (`probe_success`, `probe_duration_seconds`, `probe_http_duration_seconds{phase="resolve|connect|tls|processing|transfer"}`, `probe_http_status_code`, `probe_http_ssl`, `probe_ssl_earliest_cert_expiry`), so existing Grafana dashboards can be reused. `probe_success` is `1` only when health is `up`.

```yaml
scrape_configs:
  - job_name: anhanga-blackbox
    metrics_path: /probe
    params:
      samples: ["3"]
    authorization:
      credentials: "<ANHANGA_API_KEY>"
    static_configs:
      - targets: [https://cloudflare.com, https://github.com]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:7890
```

`anhanga_probe_latency_quantile_seconds` always carries the median (`quantile="0.5"`); the `0.95` and `0.99` series are exported only when the cycle has enough samples (at least 20 and 100 respectively), the same rule as the dashboard and the CLI, and are removed otherwise. Alert messages and the Markdown export follow the same rule. For tail latency over time, use `anhanga_probe_duration_seconds_histogram` with `histogram_quantile()`.

Targets that did not answer export no latency, grade or TLS series (no false zeros). The `anhanga_assertions_not_evaluated_total{target}` counter increments when the regex evaluator itself fails; alert on `rate(...) > 0`, otherwise a persistent evaluator failure silently disables regex assertions.

## Alerting

- **Triggers:** target offline, invalid TLS, certificate expiring, TTFB or total-latency SLO violation (median when `samples >= 2`), and grade below `min_grade`. SLOs and grade can be set per target.
- **Anti-flapping:** a problem notifies only after `failure_threshold` consecutive cycles (default 2).
- **Deduplication:** one notification, then a reminder only after `cooldown_seconds` (default 1 hour).
- **Recovery:** one notification when the problem clears.
- **Certificate expiry threshold:** the smaller of 15 days and 20% of the certificate's lifetime, so short-lived certificates are not permanently "expiring". An expiring certificate that expires or is revoked escalates to `degraded` without a green "resolved" message.
- **Delivery:** parallel and in the background, so a slow webhook never delays probing. A delivery counts only on a 2xx response. Failures are retried twice, then queued in a persistent outbox and resent with backoff (30 s, 2 min, 10 min, 30 min, 1 h), dropping after about 1 hour of attempts or 24 hours of age. Metrics: `anhanga_alert_notifications_total{kind,result}` and `anhanga_alert_outbox_pending`.
- **Providers** are detected by hostname (`api.telegram.org`; `office.com`, `outlook.com`, `logic.azure.com`, `teams.microsoft.com` and subdomains); anything else is treated as Slack-compatible. Message limits are respected on the escaped text (Slack header 150 characters, violations block 3000; Telegram 4096), truncating by line with "(+N omitted)" and always keeping the first violation.
- **Shutdown:** in-flight deliveries get 5 seconds; the rest go to the outbox.

## Persistence

SQLite (standard library, no extra dependency). It is enabled when there are targets, or when the database file already exists. The default file is `anhanga.db` in the working directory.

Stored: probe history (sparklines and uptime survive restarts), alert state (no duplicate alerts after a restart, cooldown respected), incidents, the notification outbox, and the targets added from the dashboard. The file is created with mode `0600`, and the outbox keeps only a hash of each webhook URL (the secret lives only in the configuration). A disk failure never stops monitoring: it is logged and counted in `anhanga_storage_errors_total`.

History older than `retention_days` (default 14) is pruned hourly, and the file shrinks through chunked incremental vacuum (databases created with `auto_vacuum=INCREMENTAL`). Rough sizing is about 150 bytes per probe: 10 targets every 30 seconds is about 130 MB over 30 days.

Back up with `anhanga backup`, or `sqlite3 anhanga.db ".backup out.db"`.

## Security model

- **Authentication:** with `ANHANGA_API_KEY` set, send `Authorization: Bearer <key>` or `X-API-Key`. Without a key, only direct loopback access is accepted: the `Host` header must be a loopback name and `X-Forwarded-For`, `Forwarded` and `X-Real-IP` must be absent, so a reverse proxy on the same machine is treated as external. `anhanga serve` refuses to start on a non-loopback address without a key.
- **SSRF:** blocks loopback, RFC 1918, link-local and cloud metadata (`169.254.0.0/16`, `fe80::/10`), CGNAT, IPv6 ULA, and tunneled or mapped forms (`::ffff:127.0.0.1`, 6to4, Teredo), plus non-HTTP schemes. The TCP connection is pinned to the single validated DNS answer, and the address is revalidated on every redirect. `allow_private` and `ANHANGA_ALLOW_PRIVATE` are operator-only; there is no query parameter for it.
- **Certificate-supplied URLs:** OCSP, CRL and AIA URLs come from the target's certificate, which is third-party input. They go through the same SSRF policy, do not inherit the target's `allow_private`, are size-limited (OCSP 64 KB, CRL 3 MB) and time-limited. Internal PKI needs an explicit `ANHANGA_REVOCATION_ALLOW_PRIVATE=1`.
- **Webhooks:** `POST /api/v1/webhooks/notify` only sends to URLs declared in `targets.yaml`, the alert body is always built by the server, and a `provider` or `chat_id` different from the configured one is rejected.
- **Regex assertions** run in an isolated subprocess with a 2 s timeout and a 512-character pattern limit (ReDoS protection).
- **Process:** the Docker image runs as an unprivileged user. `/healthz` returns only `{"status":"alive"}`. The UI loads no external resources (system fonts, vendored Alpine and Tailwind).
- **Review:** an automated code reading (subprocesses, SSRF, authentication, SQL, XSS, YAML) found no high-confidence vulnerability. This is not a penetration test.

Do not expose `/probe` and `/api/v1/scan` without a key: they connect to hosts chosen by the caller.

## How to read the results

### Health

`health` is `up` (HTTP ok and valid TLS), `degraded` (HTTP ok but TLS invalid: expired, hostname mismatch, untrusted root, revoked) or `down`. The exact reason is in `tls.validation_error`. Certificate days remaining can be negative (expired N days ago).

### Timings

DNS, TCP, TLS, TTFB and transfer are per-phase durations, not cumulative. `curl -w` reports cumulative times (`time_connect`, `time_appconnect`, `time_starttransfer`); subtract the previous phase to compare. `server_processing_ms` is computed only from reliable (warm) TTFB samples; a cold HTTP/2 TTFB may include about one extra RTT, and with `samples=1` the field is `null`. `end_to_end_ms` includes all redirects. DNS, TCP and TLS percentiles use only samples with a fresh connection. If a warm sample fails, the first sample is kept, later ones are skipped and the fact is noted in `timings.timing_notes`; the target is offline only if the first sample fails.

### Percentiles

P95 requires at least 20 samples and P99 at least 100, because below that they are not statistically meaningful. A scan or monitoring cycle is limited to 20 samples (to avoid loading the target), so the dashboard shows P95 only with the 20x option and never shows P99. For long-term tail latency use the histogram exported on `/metrics` with `histogram_quantile()` in Prometheus. See also [Known limitations](#known-limitations).

### Time budget

Stages after the HTTP response (TLS chain and OCSP stapling, port 80, protocol enumeration, legacy TLS, revocation, CORS, regex) each have their own deadline. If one runs out, the stages already completed are kept and the result is partial (noted in `timings.timing_notes`; regex becomes `assertions.not_evaluated`) instead of discarding a valid 200 as a timeout. Definitive assertions (`assert_final_url`, `max_payload_bytes`) are evaluated before the regex stage so they are never lost. A response that is sent but never terminated by the server (seen on `www.gnu.org`, where `curl` also hangs) exceeds the total deadline and is reported offline; that is the target's behavior.

### TLS protocols and ciphers

Each HTTPS probe enumerates, with handshakes restricted to each version, which protocols (TLS 1.0 to 1.3) and ciphers the server accepts. TLS 1.2 and earlier ciphers are found by iterative exclusion (at most 24 handshakes per version). The enumeration never holds a probe more than 3 seconds; if the target accepts many ciphers it finishes in the background and the result appears from the next cycle, cached per `hostname:port` for 6 hours (15 minutes if any state was inconclusive). At most one new enumeration per `ip:port` every 2 minutes. On a target's first probe the block may be "not evaluated".

States: `accepted`; `rejected` (only a TLS alert from the server counts: a bare `handshake_failure` does not prove a version was refused, only `protocol_version` does); `unknown` (timeout, network failure or client limitation; never treated as rejected and never cached as conclusive); and `untestable` (SSLv2 and SSLv3, which modern OpenSSL removed).

Findings: `SEC-TLS-LEGACY` (TLS 1.0 or 1.1 accepted), `SEC-TLS-WEAK-CIPHER` (NULL, anonymous, RC4, DES, 3DES, EXPORT, MD5) and `SEC-TLS-NO-PFS` (static RSA key exchange). Legacy protocols or weak ciphers cap the transport dimension of the grade at 10/40, and missing PFS deducts 5 points. If the TLS 1.0 and 1.1 check could not be completed, the dashboard shows "Not verified" and the grade does not award the modern-TLS bonus: not verified is not the same as safe. When a handshake fails outright, the error states what the server does accept (for example "accepts only TLSv1").

### Revocation

OCSP is checked actively (the response signature is verified against the issuer), with CRL as fallback (signature and `nextUpdate` checked). `tls.revocation.status` is `good`, `revoked`, `unknown`, `unavailable` or `error`. Revoked implies `tls.valid=false`, `health=degraded`, `probe_success=0`, a failing CLI gate and an alert. "Unavailable" is never reported as "not revoked". Let's Encrypt has ended OCSP, so for it only the CRL catches revocation.

Results are cached (good 30 min, revoked 1 h, failures 5 min, CRLs until `nextUpdate` or 6 h). A revocation check never holds a probe more than 4 seconds and is not cancelled: a slow CRL finishes in the background (25 s ceiling) and the next cycle reads the cache. At most 4 background checks run at once and 32 are queued. The check runs only while the certificate is still valid.

### Content-Security-Policy

`security.csp_analysis` classifies the policy as `strong`, `moderate`, `weak` or `report-only` and lists causes: `'unsafe-inline'` without nonce or hash, `'unsafe-eval'`, wildcards, `http:`, `data:`, bare `https:`, missing `script-src` or `default-src`, `object-src` other than `'none'`, missing `base-uri`, and hosts that allow bypass (JSONP, CDNs). Nonces, hashes and `'strict-dynamic'` are recognized. Multiple policies are conjunctive: a policy without `script-src` or `default-src` does not hide another policy's `'unsafe-inline'`. A Report-Only policy does not count as protection. The CSP score is proportional to quality (strong 100%, moderate 80%, weak 50%) and a weak policy produces `SEC-CSP-WEAK` with a stricter snippet.

### Cross-origin isolation headers

COOP, COEP and CORP are read from the HTTPS response. Missing COOP or COEP yields informational `SEC-COOP` and `SEC-COEP` findings with weight 0 (optional hardening; COEP breaks third-party embeds without CORP or CORS). An invalid value, which browsers ignore, is `low`. `unsafe-none` counts as absent. Missing CORP is not reported, since it only applies to resources.

### Heuristics

`Server:` is a leak only if it exposes a version. `HttpOnly` is required only for session and authentication cookies; the double-submit token names (`csrftoken`, `XSRF-TOKEN`, `X-CSRF-TOKEN`, `csrf_token`, with `__Host-`, `__Secure-` and leading `_` accepted) do not need it because JavaScript must read them, while `_csrf` (the csurf secret) stays sensitive. `error_code` is `tls_error` only for real TLS markers, never because a hostname happens to contain one.

## Validation

Protocol support (SSLv2 to TLS 1.3) was compared with `testssl.sh` 3.2.5 on 14 public hosts (`example.com`, `github.com`, `wikipedia.org`, `cloudflare.com`, `python.org`, `mozilla.org`, and the `badssl.com` hosts for TLS 1.0, 1.1, 1.2, RC4, 3DES, NULL, RC4-MD5 and DH1024) on 2026-11-14.

- The two tools agree on TLS 1.0 to 1.3 on 9 of the 14 hosts.
- `null.badssl.com`: Anhangá reports TLS 1.0 and 1.1 accepted (confirmed with `openssl s_client`, cipher `ECDHE-RSA-NULL-SHA`); `testssl.sh` says "not offered" because its socket test does not offer NULL ciphers by default.
- `rc4.badssl.com`, `3des.badssl.com`, `rc4-md5.badssl.com`: `testssl.sh` finds them accepted, while Anhangá reports `unknown` rather than "rejected", because the local OpenSSL cannot offer RC4 or 3DES and a bare `handshake_failure` does not prove refusal.
- SSLv2 and SSLv3 are reported as `untestable`; `testssl.sh` is the reference for those.
- Only protocols were compared in this run, not the grade.

Cipher coverage was checked using `testssl.sh` with its bundled OpenSSL: the TLS 1.2 cipher list was identical on `example.com` (20 ciphers), `github.com` (14) and `tls-v1-2.badssl.com` (22). Two known differences are flagged in the UI and CLI. TLS 1.3 lists only the negotiated suite (`ciphers_complete=false`), because TLS 1.3 suites cannot be selected by exclusion from Python. RC4, 3DES and SEED cannot be offered by the local OpenSSL, so a target that accepts them does not show them and does not trigger the weak-cipher finding; `legacy_ciphers_untested=true` warns that their absence proves nothing. For a definitive answer on those, use `testssl.sh` alongside.

## Known limitations

- **Not validated against live services:** webhook payloads are tested against mocks and size limits; real delivery to Slack, Microsoft Teams and Telegram has not been exercised end to end.
- **No long soak yet:** a 14-minute run against 12 targets showed stable memory (about 125 MB) and no orphaned `openssl` processes. Multi-day behavior is unverified.
- **No P99 in the dashboard or per-cycle metrics:** see [Percentiles](#percentiles). Use the histogram for tail latency.
- **TLS enumeration:** the local OpenSSL cannot test RC4, 3DES, EXPORT or SSLv3 (see [Validation](#validation)). "Rejected" means "refused every cipher this client offers".
- **Certificate chain behind load balancers:** if the chain's leaf differs from the connection's certificate (renewal mid-probe, or different certificates per backend), the chain is discarded as "not verified", so revocation can be intermittently unavailable behind such balancers. When the `s_client` queue is full the result is indistinguishable from an `openssl` failure, so under load the chain can intermittently appear "not verified".
- **Shutdown:** a caller awaiting a cancelled revocation check receives `CancelledError`; this only happens while shutting down.
- **Minor, unfixed:** the manual merge of `ContentAssertionsResult` in `probe.py` is fragile to new fields; the IDNA helper drops port `0` and empty `?` or `#` markers; the 50 ms margin that distinguishes "deadline exhausted" from "stage timeout" is a heuristic.
- **Single instance:** one worker and one process; there is no clustering.
- **Not planned for the first release:** DNS and email auditing (CAA, SPF, DMARC, DNSSEC), a dashboard layout refactor, and SSL Labs integration. See `BACKLOG.md`.

## Development

```bash
uv pip install -e ".[dev]"
pytest
```

The suite (about 500 tests) is offline except for local PKI fixtures (a real CA, CRL and OCSP responder, `s_server`) and takes roughly one minute. CI runs it on Python 3.11, 3.12 and 3.13. Regression tests are written to fail without their fix and are checked with mutation testing.

## License

MIT. See [LICENSE](LICENSE).
