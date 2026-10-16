# Anhangá 🦌🔥 (v0.2.0 — Main Candidate)

> **Auditor Tático de Borda, TLS, Latência e DevSecOps para SREs e Engenheiros de Infraestrutura**

O **Anhangá** é um motor de diagnóstico assíncrono de alta performance projetado para equipes de SRE, Plataforma e DevSecOps que sabem que um `HTTP 200 OK` isolado raramente conta toda a história.

Inspirado no guardião mitológico de olhos de fogo que vigia o perímetro, o Anhangá inspeciona profundamente a pilha de rede — desde a resolução DNS e handshakes TCP/TLS até cadeias de redirecionamento, postura criptográfica, cabeçalhos de segurança e conformidade de SLOs — antes de certificar que um endpoint está saudável.

---

## ✨ Capacidades Principais (Fases 1 a 5)

### 1. Motor de Medição Exata de Waterfall & Amostragem Estatística (Fase 1)
- **Decomposição Real e Não-Cumulativa por Fase:** Mede separadamente `dns_ms`, `tcp_ms`, `tls_ms`, `ttfb_ms` e `transfer_ms` usando instrumentação direta no transporte `httpcore`/`httpx` (`InstrumentedPinnedNetworkBackend` e `InstrumentedAsyncNetworkStream`) e leitura em *streaming* (`aiter_bytes()`), garantindo que `total_ms` seja a soma exata das fases e calculando offsets reais (`start_ms`, `duration_ms`, `end_ms`) e a **Fase Dominante (Gargalo)**.
- **Amostragem Multi-Sonda (`samples=1..50`):**
  - **Conexão Fria (*Cold Start*) vs. Reaproveitada (*Keep-Alive*):** Compara o custo da 1ª requisição completa (DNS + TCP + TLS + TTFB + Transfer) com requisições subsequentes na mesma conexão persistente (`dns_ms=0`, `tcp_ms=0`, `tls_ms=0`).
  - **Estatísticas de Cauda:** Calcula **P50 (Mediana)**, **P95**, **P99**, **Mínimo**, **Máximo**, **Média**, **Desvio Padrão** e **Jitter** (variação média absoluta entre amostras consecutivas).
- **Rastreamento Hop-by-Hop de Redirecionamentos (`301/302/303/307/308`):** Registra cada salto em `redirect_chain` com status HTTP, URL de destino, IP resolvido, protocolo negociado e breakdown completo de latência por salto.
- **Inspeção Profunda de Certificados TLS:** Extrai emissor (`Issuer`), titular (`Subject`), **SANs** (`SubjectAltName`), **Cadeia de Certificação** (`Leaf -> Intermediate -> Root`), número de série, **Fingerprint SHA-256**, datas `notBefore`/`notAfter`, dias restantes (`alert_expiring` quando `< 15` dias), versão do protocolo, cifra, bits, **OCSP Stapling** e detecção ativa/passiva de aceitação de **TLS 1.0/1.1 depreciados**.

### 2. Blindagem Anti-SSRF, Anti-DNS Rebinding & Runbook DevSecOps (Fase 2)
- **Guardião Anti-SSRF Completo (IPv4 & IPv6):**
  - Bloqueia **Loopback** (`127.0.0.0/8`, `::1/128`), **RFC 1918** (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), **Link-Local / Cloud Metadata** (`169.254.0.0/16`, `fe80::/10`), **CGNAT** (`100.64.0.0/10`), **IPv6 ULA** (`fc00::/7`), **IPv4-mapped IPv6** (`::ffff:127.0.0.1`), **6to4** (`2002::/16`), **Teredo** (`2001::/32`), zonas IPv6 (`%eth0`) e esquemas não-HTTP (`file://`, `gopher://`, `ftp://`, `dict://`, `javascript:`, `data:`).
- **Defesa Anti-DNS Rebinding (IP Pinning):** Resolve o hostname uma única vez por salto, valida todos os registros `A`/`AAAA` retornados e fixa (*pins*) o IP validado diretamente no socket TCP (`InstrumentedPinnedNetworkBackend`), preservando SNI e header `Host` e revalidando cada salto de redirecionamento.
- **Salvaguardas Operacionais:** Limite de leitura de payload em *streaming* (`max_body_bytes`, padrão `2 MiB`, teto `5 MiB`), timeouts rígidos por fase/global e **Rate Limiting** em memória por IP (`SlidingWindowRateLimiter`, HTTP `429 Too Many Requests` com `Retry-After`) com limpeza automática de chaves expiradas.
- **Auditoria DevSecOps Inteligente & Runbook Multi-Servidor:**
  - **HSTS Progressivo sem falso positivo de `preload`:** Avalia o `Strict-Transport-Security` em estágios seguros (`300s` -> `604800s` -> `2592000s`), concedendo pontuação máxima de HSTS para `max-age >= 2592000` (30 dias) sem exigir `preload` (tratado como *opt-in* opcional).
  - **Equivalência Moderna de Clickjacking:** Reconhece `Content-Security-Policy: frame-ancestors` como substituto válido para `X-Frame-Options`.
  - **Permissions-Policy, Cookies, CORS e Fingerprinting:** Audita restrição explícita `camera=()`, múltiplos cabeçalhos `Set-Cookie` (`Secure`, `HttpOnly`, `SameSite`, incluindo `SameSite=None` sem `Secure`), `Access-Control-Allow-Origin: *` e vazamentos de versão (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`).
  - **Snippets Prontos para 5 Servidores:** Gera correções para **Nginx**, **Apache**, **Caddy**, **Traefik** e **Kubernetes Ingress**.

### 3. Dashboard Tático em PT-BR com Simulador de Nota e Re-Scan (Fase 3)
- **Interface 100% em Português do Brasil (`pt-BR`)** com suporte a internacionalização (`pt-BR` / `en-US`), tipografia semântica (`font-sans` para prosa/descrições e `font-mono` para métricas/código) e contraste acessível **WCAG AA**.
- **Hero KPIs de Decisão Rápida:** Nota de Segurança (`A+` a `F`) e Latência Total (`P50`, `P95`, `P99`, `Jitter` e comparativo Conexão Fria vs. Reaproveitada) em destaque no topo do dashboard.
- **Waterfall Tático Real:** Barras proporcionais posicionadas com offsets reais (`start_ms` -> `end_ms`), cores e ícones por limiar de SLO (*Saudável*, *Atenção*, *Crítico*) e destaque visual da **Fase Dominante / Gargalo**.
- **Runbook Interativo com Simulador de Projeção de Nota:** Permite marcar correções numeradas (`#1`, `#2`, ...) e visualizar em tempo real a projeção de pontuação e nota (*"Ao aplicar #1, #2, sua nota sobe para A (90/100)"*), copiar snippets com 1 clique e executar **Re-escanear Agora** com cálculo de **Delta de Evolução**.
- **Vigilância Contínua com Sparklines SVG & Exportação:** Cards de monitoramento com minigráficos SVG das últimas sondagens e exportação via **Link Permanente (`?scan=...`)**, **JSON** e **Markdown**.

### 4. CLI CI/CD (`anhanga check`), Métricas `blackbox_exporter` e Webhooks (Fase 4)
- **Modo CLI Headless para Pipelines CI/CD:**
  - Quality Gates configuráveis via `--min-grade`, `--max-ttfb` e `--max-total`.
  - **Exit Codes Padronizados:** `0` (Gates aprovados), `1` (Alvo offline, violação de SLO ou nota abaixo do mínimo), `2` (Parâmetros inválidos, erro de DNS/rede ou bloqueio Anti-SSRF).
  - **Formatos de Saída:** Tabela **Rich** (`text`), **JSON** estruturado (`json`) e **SARIF v2.1.0** (`sarif`) para integração nativa com **GitHub Code Scanning / Security Tab**.
- **Compatibilidade com Prometheus `blackbox_exporter`:**
  - Endpoints `/metrics` e `/probe?target=<url>` expondo métricas em **segundos** com os mesmos nomes e labels do `blackbox_exporter` (`probe_success`, `probe_duration_seconds`, `probe_http_duration_seconds{phase="resolve|connect|tls|processing|transfer"}`, `probe_http_status_code`, `probe_http_redirects`, `probe_http_ssl`, `probe_ssl_earliest_cert_expiry`), além das métricas estendidas `anhanga_probe_*` (quantis P50/P95/P99, jitter, cold vs. warm e security score).
- **Alertas via Webhooks (Slack, Microsoft Teams e Telegram):**
  - Construção nativa de payloads (Slack *Block Kit*, Microsoft Teams *MessageCard* e Telegram *HTML* com escape seguro de caracteres especiais) e envio protegido pelo Guardião Anti-SSRF via CLI (`--webhook-url`) ou API (`POST /api/v1/webhooks/notify`).

### 5. Governança Multi-Agente, Revisão Cruzada e Qualidade (Fase 5)
- Fluxo documentado em [AGENTS.md](AGENTS.md) com isolamento por especialidade, Revisão Cruzada (Backend ↔ Segurança) e suíte automatizada de **28 testes e 54 subtestes** (`pytest -v`).

---

## 📦 Instalação e Execução

```bash
# 1. Crie o ambiente virtual e instale o projeto (com dependências de desenvolvimento/teste)
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e ".[dev]"

# 2. Inicie o servidor Web + API FastAPI na porta 7890
uvicorn anhanga.main:app --reload --host 127.0.0.1 --port 7890
```

Acesse o **Dashboard Tático** em `http://127.0.0.1:7890`.

---

## 🖥️ Uso da CLI em Pipelines CI/CD (`anhanga check`)

```bash
# Auditoria interativa no terminal com Quality Gates de Segurança e Latência
anhanga check https://cloudflare.com --min-grade B --max-ttfb 500ms --max-total 1.5s --samples 3

# Exportação em formato JSON para automação
anhanga check https://cloudflare.com --min-grade A --max-ttfb 300ms --format json --output report.json

# Exportação em formato SARIF v2.1.0 para GitHub Code Scanning
anhanga check https://cloudflare.com --min-grade A --max-ttfb 400ms --format sarif --output anhanga.sarif

# Disparo automático de alerta via Webhook (Slack, Teams ou Telegram) em caso de violação
anhanga check https://example.com \
  --min-grade B \
  --max-ttfb 400ms \
  --webhook-url "https://hooks.slack.com/services/T000/B000/X000" \
  --webhook-provider slack
```

### Exit Codes da CLI
| Código | Significado |
| :---: | :--- |
| `0` | Todos os Quality Gates (disponibilidade, nota mínima de segurança e SLOs de latência) foram aprovados. |
| `1` | Falha nos Quality Gates: alvo offline (`HTTP >= 400`), nota de segurança inferior a `--min-grade` ou latência acima de `--max-ttfb`/`--max-total`. |
| `2` | Erro de execução ou segurança: parâmetros inválidos, falha de resolução DNS ou bloqueio pelo Guardião Anti-SSRF. |

---

## 📊 Observabilidade Prometheus (`/metrics` e `/probe`)

Exemplo de configuração de *scrape* no `prometheus.yml` (compatível com dashboards do `blackbox_exporter`):

```yaml
scrape_configs:
  - job_name: "anhanga-edge-probe"
    metrics_path: /probe
    params:
      samples: ["3"]
    static_configs:
      - targets:
          - https://cloudflare.com
          - https://github.com
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:7890
```

---

## 🧪 Suíte de Testes e Qualidade

Para executar a suíte completa de testes unitários e de integração (`pytest`):

```bash
pytest -v
```