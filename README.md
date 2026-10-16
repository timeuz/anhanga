# Anhangá 🦌🔥

> **Spectral Edge, TLS & Latency Auditor for SRE and DevSecOps**

O **Anhangá** é um motor assíncrono de diagnóstico de rede, auditoria de borda e observabilidade projetado para engenheiros de infraestrutura, SREs e profissionais de DevSecOps que sabem que um `HTTP 200 OK` isolado raramente conta toda a história.

Inspirado no guardião mitológico de olhos de fogo que vigia o perímetro, o Anhangá inspeciona toda a pilha de conexão — desde a resolução DNS e handshakes TCP/TLS até cadeias de redirecionamento, postura criptográfica, cabeçalhos de segurança e conformidade de SLOs — tanto via **Dashboard Web**, **CLI para CI/CD** quanto via **Métricas Prometheus**.

---

## 🚀 Principais Recursos

### 1. Diagnóstico Tático de Latência e Waterfall Real
- **Decomposição Não-Cumulativa por Fase:** Mede isoladamente o tempo gasto em **DNS Lookup**, **TCP Handshake**, **TLS Handshake**, **TTFB (Processamento no Backend)** e **Transferência de Conteúdo**, apresentando offsets exatos de início e fim (`start_ms` → `end_ms`) e identificando automaticamente a **Fase Dominante (Gargalo)** com classificação visual por SLO.
- **Amostragem Estatística Multi-Sonda:** Permite executar múltiplas amostras por verificação (`--samples N`), calculando **P50 (Mediana)**, **P95**, **P99**, **Média**, **Min/Max** e **Jitter**, além de comparar o tempo de **Conexão Fria (*Cold Start*)** com **Conexão Reaproveitada (*Keep-Alive*)**.
- **Rastreamento de Cadeia de Redirects:** Mapeia cada salto (`301`, `302`, `303`, `307`, `308`) de `HTTP -> HTTPS` ou `apex -> www` com status, IP resolvido e latência individual por hop.

### 2. Inspeção Profunda de Certificados TLS
- Verifica validade temporal, dias restantes até a expiração (com alerta preventivo abaixo de 15 dias), Emissor (`Issuer`), Titular (`Subject`), Número de Série e **Fingerprint SHA-256**.
- Extrai todos os **SANs (`Subject Alternative Names`)** e reconstrói a **Cadeia de Certificação X.509** (`Leaf -> Intermediate -> Root CA`).
- Inspeciona versão do protocolo negociado, suíte de cifra (`cipher` e `bits`), status de **OCSP Stapling** e detecta se o servidor ainda aceita versões legadas inseguras (**TLS 1.0 / TLS 1.1**).

### 3. Auditoria DevSecOps de Borda e Runbook Multi-Servidor
- **Cálculo de Nota de Segurança (`A+` até `F`):** Avalia cabeçalhos essenciais de proteção de borda:
  - `Strict-Transport-Security` (**HSTS** com recomendações progressivas de rollout: `300s` → `1 semana` → `1 mês+`, tratando `preload` como *opt-in* voluntário).
  - `Content-Security-Policy` (**CSP**), reconhecendo a diretiva moderna `frame-ancestors` como proteção equivalente ao `X-Frame-Options` contra Clickjacking.
  - `Permissions-Policy` (incluindo verificação explícita de bloqueio `camera=()`) e `X-Content-Type-Options: nosniff`.
  - `Referrer-Policy`, flags de segurança em `Set-Cookie` (`Secure`, `HttpOnly`, `SameSite`), políticas de **CORS** permissivas (`Access-Control-Allow-Origin: *`) e vazamento de versão de tecnologia (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`).
- **Runbook de Remediação Interativo:** Gera snippets prontos para copiar e colar em **Nginx**, **Apache**, **Caddy**, **Traefik** e **Kubernetes Ingress**, com **Simulador de Projeção de Nota** em tempo real e botão **Re-escanear** com cálculo de delta de evolução.

### 4. Proteção Nativa Anti-SSRF e Anti-DNS Rebinding
- Bloqueia por padrão tentativas de sondar redes privadas ou internas: Loopback (`127.0.0.0/8`, `::1`), RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Link-Local e Cloud Metadata (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), IPv6 ULA (`fc00::/7`) e endereços tunelados/mapeados (`::ffff:127.0.0.1`, 6to4, Teredo), além de esquemas não-HTTP (`file://`, `gopher://`, `ftp://`).
- Prende (*pins*) a conexão TCP diretamente ao IP validado na resolução única de DNS (prevenindo ataques de *DNS Rebinding*) e revalida o IP a cada redirecionamento.
- Conta com controle de taxa de requisições (*Rate Limiting* por IP), timeouts rígidos e limite máximo de leitura de payload. Para auditorias em laboratórios ou redes internas autorizadas, oferece a flag explícita `--allow-private` / `allow_private: true`.

---

## 📦 Instalação

Requer **Python 3.11+**. Recomendado utilizar o gerenciador [`uv`](https://docs.astral.sh/uv/):

```bash
# Cria o ambiente virtual e instala o Anhangá
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e .
```

---

## 🌐 Executando o Dashboard Web e a API

Para iniciar o servidor web e a API FastAPI na porta `7890`:

```bash
anhanga serve --host 127.0.0.1 --port 7890
# Ou diretamente via uvicorn:
uvicorn anhanga.main:app --reload --host 127.0.0.1 --port 7890
```

- **Dashboard Web Interativo (PT-BR / EN):** `http://127.0.0.1:7890`
  - Permite executar inspeções sob demanda, simular correções no Runbook, comparar re-escaneamentos e exportar relatórios em **Link Permanente**, **JSON** e **Markdown**.
- **Documentação OpenAPI / Swagger:** `http://127.0.0.1:7890/docs`
- **Healthcheck (Kubernetes Liveness/Readiness):** `http://127.0.0.1:7890/healthz`

---

## 🎯 Vigilância Contínua com `targets.yaml`

O arquivo **`targets.yaml`** na raiz do projeto (ou apontado pela variável de ambiente `ANHANGA_CONFIG`) define os endpoints que o Anhangá monitora continuamente em background assim que o servidor é iniciado.

Essa sondagem periódica alimenta automaticamente:
1. Os cards de **Vigilância Contínua** no Dashboard Web (com gráficos *Sparkline* da evolução de latência);
2. As métricas exportadas em `/metrics` para coleta pelo Prometheus;
3. O disparo automático de alertas via **Webhooks** (Slack, Microsoft Teams e Telegram) caso um alvo fique indisponível ou apresente certificado TLS prestes a expirar.

Para começar, copie o arquivo de exemplo:

```bash
cp targets.example.yaml targets.yaml
```

Estrutura do `targets.yaml`:

```yaml
interval_seconds: 30   # Intervalo em segundos entre os ciclos de sondagem em background
samples: 3             # Quantidade de amostras por ciclo (calcula P50, P95, P99 e Jitter)
allow_private: false   # Defina como true apenas para monitorar serviços de rede interna/lab

targets:
  - https://cloudflare.com
  - https://github.com
  - https://news.ycombinator.com

# Opcional: Webhooks para notificações automáticas de incidentes/expiração TLS
webhooks:
  - url: "https://hooks.slack.com/services/T000/B000/X000"
    provider: "slack"
  - url: "https://outlook.office.com/webhook/..."
    provider: "teams"
  - url: "https://api.telegram.org/bot<TOKEN>/sendMessage"
    provider: "telegram"
    telegram_chat_id: "-1001234567890"
```

---

## 🖥️ Modo CLI para Pipelines de CI/CD (`anhanga check`)

Use o comando `anhanga check` em esteiras de CI/CD (GitHub Actions, GitLab CI, Jenkins, Azure DevOps) para validar Quality Gates de performance e segurança após o deploy:

```bash
# Verifica se o endpoint atinge nota mínima B e TTFB abaixo de 500ms (com 3 amostras)
anhanga check https://seudominio.com --min-grade B --max-ttfb 500ms --samples 3

# Define limite também para a latência total (ex: 1.5s)
anhanga check https://api.seudominio.com --min-grade A --max-ttfb 300ms --max-total 1.5s

# Exporta o resultado em JSON para consumo por scripts da pipeline
anhanga check https://seudominio.com --min-grade B --format json --output relatorio.json

# Exporta em formato SARIF v2.1.0 para integração com a aba Security (Code Scanning) do GitHub
anhanga check https://seudominio.com --min-grade A --max-ttfb 400ms --format sarif --output anhanga.sarif

# Envia alerta para Slack, Teams ou Telegram se os Quality Gates falharem
anhanga check https://seudominio.com \
  --min-grade B \
  --max-ttfb 500ms \
  --webhook-url "https://hooks.slack.com/services/T000/B000/X000" \
  --webhook-provider slack
```

### Exit Codes da CLI
| Exit Code | Condição |
| :---: | :--- |
| `0` | Alvo online e aprovado em todos os critérios (`--min-grade`, `--max-ttfb`, `--max-total`). |
| `1` | Falha de Quality Gate: alvo indisponível (`HTTP >= 400`), nota de segurança abaixo de `--min-grade` ou latência acima dos limites. |
| `2` | Erro de execução/configuração, falha de DNS ou bloqueio pelo Guardião Anti-SSRF. |

---

## 📊 Observabilidade Prometheus e Compatibilidade com `blackbox_exporter`

O Anhangá expõe todas as durações em **segundos** e fornece tanto métricas estendidas (`anhanga_probe_*`) quanto as séries nativas do **`blackbox_exporter`** (`probe_success`, `probe_duration_seconds`, `probe_http_duration_seconds{phase="resolve|connect|tls|processing|transfer"}`, `probe_http_status_code`, `probe_http_ssl`, `probe_ssl_earliest_cert_expiry`), permitindo reaproveitar dashboards Grafana existentes sem alterações.

- **`GET /metrics`**: Retorna as métricas consolidadas dos alvos monitorados via `targets.yaml`.
- **`GET /probe?target=<url>&samples=3`**: Executa uma sondagem sob demanda no padrão multi-target do Prometheus `blackbox_exporter`.

Exemplo de configuração no `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "anhanga-blackbox"
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