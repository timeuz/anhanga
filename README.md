# Anhangá 🦌🔥

> **Spectral Edge, TLS & Latency Auditor for SRE and DevSecOps**

O **Anhangá** é um motor assíncrono de diagnóstico de rede, auditoria de borda e observabilidade projetado para engenheiros de infraestrutura, SREs e profissionais de DevSecOps que sabem que um `HTTP 200 OK` isolado raramente conta toda a história.

Inspirado no guardião mitológico de olhos de fogo que vigia o perímetro, o Anhangá inspeciona toda a pilha de conexão — desde a resolução DNS e handshakes TCP/TLS até cadeias de redirecionamento, postura criptográfica, cabeçalhos de segurança e conformidade de SLOs — tanto via **Dashboard Web**, **CLI para CI/CD** quanto via **Métricas Prometheus**.

---

## 🚀 Principais Recursos

### 1. Diagnóstico Tático de Latência e Waterfall Real
- **Decomposição Não-Cumulativa por Fase:** Mede isoladamente o tempo gasto em **DNS Lookup**, **TCP Handshake**, **TLS Handshake**, **TTFB (tempo até o primeiro byte; inclui 1 RTT de rede)** e **Transferência de Conteúdo**, apresentando offsets exatos de início e fim (`start_ms` → `end_ms`) e identificando automaticamente a **Fase Dominante (Gargalo)** com classificação visual por SLO.
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

---

## 🔐 Segurança da API (hardening)

- **Autenticação:** defina `ANHANGA_API_KEY`; as rotas `/api/*`, `/probe` e `/metrics` exigem `Authorization: Bearer <chave>` (ou `X-API-Key`). **Sem a chave, apenas acesso loopback direto é aceito** (requisições com `X-Forwarded-For`/`Forwarded`/`X-Real-IP` são recusadas). Atrás de proxy reverso, a chave é obrigatória.
- **SSRF:** a política de IPs privados é do operador: `ANHANGA_ALLOW_PRIVATE=1` (rotas HTTP) ou `allow_private` no `targets.yaml`. Não existe mais parâmetro de query para isso.
- **Webhooks:** `POST /api/v1/webhooks/notify` só envia para URLs declaradas em `webhooks:` do `targets.yaml`; o corpo do alerta é sempre gerado pelo servidor.
- **Regex de asserção:** executada em subprocesso com timeout de 2 s e padrão limitado a 512 caracteres.
- **Estado e métricas:** apenas alvos do `targets.yaml` entram no dashboard e no `/metrics`. Scans avulsos e `/probe` não criam séries.
- **Rate limit:** `samples=N` consome N requisições. `ANHANGA_TRUSTED_PROXIES` vem vazio por padrão (XFF ignorado); liste os IPs dos seus proxies para honrá-lo.


---

## ✅ Semântica de saúde e diagnóstico (v0.2.x)

- **`health`** em todo resultado: `up` (HTTP ok e TLS válido), `degraded` (HTTP ok, **TLS inválido**: expirado, hostname divergente, raiz não confiável…) ou `down`. O motivo exato vem em `tls.validation_error`. `probe_success` (Prometheus) só vale 1 para `up`.
- **CLI:** `anhanga check` reprova (exit 1) certificado inválido; use `--allow-invalid-cert` para tolerar. Erros de argumento/configuração saem com **exit 3** (nota abaixo do mínimo = 2).
- **API:** falhas sem resposta do alvo retornam `400` (URL inválida), `403` (Anti-SSRF), `502` (DNS/conexão/TLS) ou `504` (timeout), com `{"detail": {"error_code", "message", "target_url"}}`. Achados da sondagem (5xx do alvo, asserção, TLS inválido) continuam `200`.
- **OCSP e cadeia X.509:** obtidos via `openssl s_client` (o módulo `ssl` do Python não os expõe). Sem o binário `openssl`, o campo vira "Não verificado" (`ocsp_stapling: null`), nunca "ausente".
- **Dias de validade** podem ser negativos (expirado há N dias).
- **Latência:** `server_processing_ms` só é calculado a partir de TTFB confiável (amostras quentes). TTFB frio em HTTP/2 pode incluir ~1 RTT extra; com `samples=1` o campo é `null`. `end_to_end_ms` inclui todos os redirects. Percentis de DNS/TCP/TLS usam só amostras com conexão nova.
- **Alvos sem resposta** não geram séries de latência/nota/TLS em `/metrics` (nada de zeros falsos); o dashboard mostra "—".
- **Heurísticas:** `Server:` só é vazamento se expõe versão; `HttpOnly` só é exigido de cookies de sessão/autenticação (`ANHANGA_SENSITIVE_COOKIE_REGEX` ajusta).


---

## 🔔 Alertas com estado e configuração validada

O `targets.yaml` é **validado na carga** (erros e ajustes vão para o log; entradas inválidas são descartadas, o servidor não cai) e **recarregado a quente** quando o arquivo muda. Veja `targets.example.yaml` para todas as opções.

- **Anti-flapping:** um problema só notifica após `failure_threshold` ciclos consecutivos (padrão 2).
- **Deduplicação:** notifica **uma vez**; repete como *lembrete* só após `cooldown_seconds` (padrão 1 h; `0` = sem lembretes).
- **Recuperação:** uma notificação quando o problema some (`recovery_threshold`, `notify_recovery`).
- **Gatilhos:** alvo offline, TLS inválido, certificado expirando, SLO de TTFB/latência total (`slo:`; usa a mediana quando `samples ≥ 2`) e nota abaixo de `min_grade`. SLO e nota podem ser definidos por alvo.
- **Entrega:** em paralelo e em background (webhook lento não atrasa as sondagens), com timeout e uma nova tentativa. Se ainda falhar, a notificação vai para a **outbox persistente** e é reenviada com backoff (30 s, 2 min, 10 min, 30 min, 1 h; desiste após ~1 h ou 24 h de idade). Métricas: `anhanga_alert_notifications_total{kind,result=sent|queued|dropped|failed}` e `anhanga_alert_outbox_pending`.
- **Persistência:** o estado dos alertas sobrevive a reinícios (veja abaixo), então um problema ainda ativo não é notificado de novo.

## 🧪 Desenvolvimento

```bash
uv pip install -e ".[dev]"
pytest          # sem rede; ~3 s
```


## 💾 Persistência (SQLite)

Ativa automaticamente quando há alvos no `targets.yaml` (stdlib `sqlite3`, sem dependência extra). Arquivo padrão `anhanga.db` no diretório de execução; ajuste com `ANHANGA_DB_PATH` ou:

```yaml
storage:
  enabled: true        # false desliga (o monitor segue funcionando, só sem histórico)
  path: /var/lib/anhanga/anhanga.db
  retention_days: 14   # histórico e incidentes encerrados mais antigos são podados a cada hora
```

O que fica salvo: **histórico de sondagens** (sparkline e uptime sobrevivem a reinício), **estado dos alertas** (sem alerta duplicado após reiniciar; cooldown respeitado), **incidentes** (início no 1º ciclo com falha, fim na recuperação) e a **outbox** de notificações. O arquivo é criado com permissão `0600` e a outbox guarda só um hash da URL do webhook (o segredo fica apenas na configuração). Falha de disco nunca derruba o monitor: é logada e contada em `anhanga_storage_errors_total`.

| Endpoint (exigem a API key, como os demais `/api/*`) | Retorna |
|---|---|
| `GET /api/v1/history?target=&hours=24&max_points=300` | série agregada: checks, up/degraded/down e latência média/mín/máx por bucket |
| `GET /api/v1/uptime[?target=]` | `uptime_pct` (health=up) e `availability_pct` (HTTP respondeu) em 24h/7d/30d, com `covered_seconds` (cobertura real dos dados) |
| `GET /api/v1/incidents[?target=&open_only=true&limit=]` | incidentes abertos e encerrados, com duração |

Estimativa de espaço: ~150 B por sondagem (10 alvos a cada 30 s ≈ 130 MB com 30 dias de retenção). Backup: copie o `.db` com o servidor parado, ou use `sqlite3 anhanga.db ".backup out.db"`.


## 🖥️ Dashboard operacional

- **Auto-atualização** a cada 15 s (pausa com a aba oculta; liga/desliga e a preferência fica no navegador) com indicador "Atualizado há Ns".
- **Resumo no topo** (Todos / Online / Degradado / Offline) que também filtra os cards, e **ordenação** por pior status, nome, maior latência ou pior nota.
- **Uptime 24h por card**, com a cobertura real dos dados ("dados de 28 s" quando o banco é novo) em vez de fingir uma janela cheia.
- **Incidentes recentes**: abertos e resolvidos, com início, duração e motivo.
- Sem persistência (desativada ou sem alvos), o dashboard esconde uptime e incidentes e avisa por quê. Com `ANHANGA_API_KEY`, a chave é pedida uma única vez por carga de página.


## 🔎 Revogação de certificado

Além de validade, cadeia e hostname, o Anhangá verifica se o certificado **foi revogado**: **OCSP ativo** (resposta com assinatura verificada contra o emissor) e **CRL como fallback** (assinatura verificada, `nextUpdate` conferido). O Let's Encrypt encerrou o OCSP, então para ele só o CRL pega a revogação (testado contra `revoked.badssl.com`).

- Resultado em `tls.revocation` (`status`: `good` | `revoked` | `unknown` | `unavailable` | `error`, `method`, `revoked_at`, `responder`). **Revogado ⇒ `tls.valid=false`**, `health=degraded`, `probe_success=0`, gate do CLI reprova e o alerta dispara. "Não verificável" nunca é reportado como "não revogado".
- **Segurança:** as URLs de OCSP/CRL vêm do certificado (terceiros). Toda requisição passa pela política Anti-SSRF (IP validado e fixado, redirects revalidados), com limites de tamanho (OCSP 64 KB, CRL 3 MB) e timeout.
- **Cache** (bom 30 min, revogado 1 h, falhas 5 min; CRL até `nextUpdate`/6 h) para não martelar os respondedores a cada ciclo. Desligue com `ANHANGA_REVOCATION_CHECK=0`.
- Requer o binário `openssl` (sem ele: "não verificável"). Só roda se o certificado ainda é válido.

## 🛡️ Qualidade da Content-Security-Policy

Ter CSP não basta. `security.csp_analysis` classifica a política (`strong` / `moderate` / `weak` / `report-only`) e lista as causas: `'unsafe-inline'` sem nonce/hash, `'unsafe-eval'`, `*`, `http:`, `data:`, `https:` genérico, `script-src`/`default-src` ausentes, `object-src` diferente de `'none'`, `base-uri` ausente e hosts que permitem bypass (JSONP/CDNs). Nonce/hash e `'strict-dynamic'` são reconhecidos. Várias políticas são conjuntivas (uma fraqueza só vale se todas a tiverem).

- **Report-Only não conta como proteção** (não bloqueia nada); antes uma CSP só em Report-Only ganhava a nota cheia.
- A pontuação da CSP é proporcional à qualidade (forte 100%, moderada 80%, fraca 50%) e gera o finding `SEC-CSP-WEAK` com snippet de política mais rígida.

## 🔒 Protocolos e cifras TLS

Cada sondagem HTTPS enumera, com handshakes restritos a cada versão, quais protocolos (TLS 1.0–1.3) e
cifras o servidor aceita. As cifras de TLS ≤ 1.2 são descobertas por exclusão iterativa (máx. 24
handshakes por versão). O resultado fica em cache por 6 h por `ip:porta:host`, então o custo extra no
alvo é de ~10–40 handshakes a cada 6 h, e não a cada ciclo. `ANHANGA_TLS_ENUM=0` desliga.

- **Findings:** `SEC-TLS-LEGACY` (TLS 1.0/1.1 aceito), `SEC-TLS-WEAK-CIPHER` (NULL, anônimas,
  RC4/DES/3DES, EXPORT, MD5) e `SEC-TLS-NO-PFS` (RSA estática, sem forward secrecy). Legado ou cifra fraca
  limitam a dimensão de transporte a 10/40; falta de PFS desconta 5 pontos.
- **Handshake que falha:** em vez de só "offline", o erro diz o que o servidor aceita (ex.: "aceita apenas:
  TLSv1") e o resultado traz a enumeração.
- **Estados:** `accepted`, `rejected` (só um alerta TLS do servidor conta), `unknown` (timeout, falha de
  rede ou limitação do cliente; nunca vira "recusado" nem entra no cache) e `untestable` (SSLv2/SSLv3).

**Prazos:** a enumeração nunca segura a sondagem por mais de 3 s. Se o alvo aceita muitas cifras (ex.: ~20 em TLS 1.2),
ela termina em segundo plano e o resultado aparece a partir do ciclo seguinte (cache por `hostname:porta`). No máximo uma
enumeração nova por `ip:porta` a cada 2 min. A checagem de revogação tem orçamento próprio de 4 s; se estourar, vira
`error` em cache por 5 min, nunca derruba a sondagem.

**Limites:** o teste usa o OpenSSL do sistema, que não oferece RC4/3DES/EXPORT nem SSLv3. Um servidor que só
aceita essas cifras aparece como "nenhum protocolo testável aceito", não como "usa RC4". "Recusado" significa
"recusou todas as cifras que este cliente oferece".

## 🧱 Isolamento de origem cruzada (COOP / COEP / CORP)

Os três headers são lidos da resposta HTTPS e aparecem em `present_headers`. A ausência de COOP/COEP gera
findings `SEC-COOP`/`SEC-COEP` com severidade `info` e **peso 0**: são endurecimentos opcionais (o COEP quebra
embeds de terceiros sem CORP/CORS), então não alteram a nota. Valor inválido (que o navegador ignora) vira `low`.
`unsafe-none` conta como ausente. A ausência de CORP não é apontada, já que só faz sentido para recursos
(imagens, scripts) e não para páginas HTML.

## ⚙️ Configuração: regras de validação

- **Booleanos estritos:** `allow_private`, `alerting.notify_recovery` e `storage.enabled` aceitam `true/false`,
  `yes/no`, `on/off`, `1/0` (inclusive como string vinda de `${VAR}`). Qualquer outro valor (ex.: variável vazia) é
  um erro registrado e cai no padrão **seguro** (`allow_private=false`). Nunca é interpretado como "verdadeiro".
- **Recarga a quente:** se o `targets.yaml` salvo estiver ilegível ou com YAML inválido, a recarga é rejeitada e a
  configuração anterior continua valendo (alvos, estado de alertas e incidentes abertos ficam intactos).
- **Alvos duplicados** são detectados pela URL normalizada (`example.com` = `https://example.com` = `HTTPS://EXAMPLE.COM`).
- **Dashboard:** o HTML é público, mas os dados em cache só vão embutidos para quem está autorizado.
- **Desligamento:** entregas de alerta em voo ganham 5 s para concluir; as que não concluírem vão para a outbox.

## 🔔 Entrega de alertas e revogação: detalhes de segurança

- **Webhook só conta como entregue com resposta 2xx.** 4xx/5xx/429 são falha: 2 tentativas imediatas, depois a
  outbox reenvia com backoff (e só remove o item quando o destino responde 2xx).
- **URLs de OCSP/CRL/AIA vêm do certificado do alvo (terceiro) e NÃO herdam o `allow_private` dele.** Sem isso, um
  certificado hostil faria o monitor requisitar `169.254.169.254` ou a rede interna. Para PKI interna com
  respondedor em IP privado, o operador libera explicitamente com `ANHANGA_REVOCATION_ALLOW_PRIVATE=1`.
- **A revogação nunca segura a sondagem por mais de 4 s e não é cancelada.** Se o CRL for grande e demorar mais, o
  campo sai como `unavailable` ("verificação em andamento") e o trabalho termina em segundo plano (teto de 25 s); o
  ciclo seguinte lê o resultado do cache. Processos `openssl` são sempre encerrados, inclusive em cancelamento.

## 🧩 Asserções de conteúdo (regex) e execução sem instalar o pacote

O avaliador de regex (anti-ReDoS, subprocesso com timeout de 2 s) roda por **caminho de arquivo** e só usa a
biblioteca padrão, então funciona também com `PYTHONPATH=src` (sem `pip install`). Se o próprio avaliador falhar,
a asserção reporta "Avaliador de regex indisponível" (falha do Anhangá), nunca "Regexp inválida" (reservado a
padrões realmente inválidos). O diagnóstico de handshake TLS acompanha o `timeout` pedido (no máximo 2× e 10 s).

## 🧹 Refinamentos de payload, cookies e erros

- **Webhooks:** as mensagens do AlertManager são a fonte de verdade. O estado do resultado só completa o que elas
  não cobrem (por tópico, não por igualdade de texto), e em lembrete/recuperação nada é acrescentado.
- **Cadeia/OCSP grampeado:** `openssl s_client` tem cache de 5 min por `host:porta` (invalidado se o certificado da
  conexão mudou, ou seja, após uma renovação) e no máximo 8 execuções simultâneas.
- **Cookies:** só os *nomes* de token de double-submit (`csrftoken`, `XSRF-TOKEN`, `X-CSRF-TOKEN`, `csrf_token`) não
  exigem `HttpOnly` (precisam ser legíveis por JS). `_csrf` (segredo do csurf), `csrf_session`, `auth_xsrf_sid` etc.
  continuam sensíveis. `ANHANGA_SENSITIVE_COOKIE_REGEX` inválida é registrada e ignorada (usa o padrão, com as
  exceções do padrão), em vez de derrubar a aplicação; válida, vale como escrita.
- **Erros:** `tls_error` só para marcadores reais de TLS (nunca por um hostname como `classless.example`). O retry
  após certificado inválido usa só o prazo que sobrou, e timeout/SSRF nele recebem o mesmo tratamento do 1º passe.

## ⚖️ Concorrência, prazos e contratos (revisão 3)

- **Cadeia/OCSP grampeado (`openssl s_client`):** no máx. 8 simultâneos, com a espera pela vaga dentro do prazo da
  etapa (se não houver vaga, a etapa degrada para "não verificado" naquele ciclo, nunca derruba a sondagem),
  *single-flight* por `host:porta` e cache que só vale quando o certificado da conexão atual é conhecido e igual.
- **Revogação em segundo plano:** no máx. 4 checagens simultâneas; no desligamento as pendentes são canceladas
  (e os `openssl` mortos). Tarefas herdadas de outro event loop são ignoradas.
- **Asserções de regex:** se o *avaliador* falhar (fork/arquivo), a asserção fica em `assertions.not_evaluated`
  (visível no dashboard), sem reprovar o alvo nem disparar alerta: é falha do Anhangá, não do alvo.
- **`error_code`:** `tls_error` cobre também `EOF occurred in violation of protocol (_ssl.c:...)` e alertas
  `tlsv1x/sslv3 alert ...`; um hostname parecido (`tlsv13-alert.example`) não conta.
- **Retry após certificado inválido:** só tenta com ≥ 1 s de prazo total restante; a mensagem de timeout cita o
  prazo realmente usado.
- **Webhooks:** o motivo do OFFLINE é completado em qualquer evento (alerta, lembrete, reenvio).

## 🔧 Refinamentos da revisão 4 e limites conhecidos

- **Asserção não avaliada:** além da linha no dashboard, cada ocorrência incrementa
  `anhanga_assertions_not_evaluated_total{target}` e gera um log `WARNING`. **Alerte em `rate(...) > 0`**: sem isso,
  uma falha persistente do avaliador deixa as asserções de regex sem efeito em silêncio.
- **Fila de revogação:** no máx. 32 checagens pendentes (acima disso, "fila cheia" na hora) e no máx. 60 s de espera
  por vaga; quem desiste não é cacheado e tenta no ciclo seguinte.
- **Cadeia `s_client`:** se a folha da cadeia obtida não for a da conexão atual (renovação no meio, ou balanceador
  servindo certificados diferentes por backend), a cadeia é descartada ("não verificado"). Atrás de um balanceador com
  certificados distintos por backend, a checagem de revogação pode ficar indisponível de forma intermitente.
- **Cookies:** a exceção de double-submit aceita `__Host-`/`__Secure-` e `_` inicial (`__Host-csrf-token`, `_csrf_token`).
- **`error_code`:** `_ssl.c` só conta no formato `(_ssl.c:NNNN)`; a mensagem de timeout cita sempre o prazo total.
- **Limites conhecidos (não corrigidos):** no desligamento, quem aguarda uma checagem cancelada recebe
  `CancelledError` (só ocorre ao encerrar); a fila cheia do `s_client` devolve o mesmo `([], None)` de uma falha do
  `openssl`, então sob carga a cadeia aparece como "não verificada" de forma intermitente.

## 📏 Como ler os números e limites de uso

- **Tempos por fase, não acumulados:** DNS, TCP, TLS, TTFB e transferência são durações de cada fase. O `curl -w`
  reporta tempos *acumulados* (`time_connect`, `time_appconnect`, `time_starttransfer`): para comparar, subtraia a fase anterior.
- **Protocolos/cifras TLS aparecem a partir do 2º ciclo:** a enumeração roda em segundo plano (orçamento de poucos
  segundos por sondagem) e fica em cache por 6 h. Na 1ª sondagem de um alvo, e no `anhanga check` de execução única,
  o bloco pode vir vazio ("não avaliado"), nunca "sem protocolos".
- **Transferência que não termina:** se o servidor envia a resposta mas não a encerra (visto em `www.gnu.org`, onde o
  `curl` também trava), a sondagem estoura o prazo total e o alvo é dado como OFFLINE. É o comportamento do alvo, não do monitor.
- **Autenticação sem `ANHANGA_API_KEY`:** só é aceito acesso direto por loopback **com** `Host` de loopback
  (`localhost`, `127.0.0.1`, `::1`) e sem `X-Forwarded-For`/`Forwarded`/`X-Real-IP`. Um proxy reverso na mesma máquina
  encaminha o `Host` público e é tratado como externo. `anhanga serve` em endereço fora do loopback **recusa iniciar**
  sem chave. Gere uma com `anhanga keygen` (veja abaixo) e não publique `/probe` e `/api/v1/scan` sem ela
  (eles conectam a hosts escolhidos pelo chamador).
- **Revisão de segurança:** uma leitura automatizada do código (subprocessos, SSRF, autenticação, SQL, XSS, YAML) não
  encontrou vulnerabilidade de alta confiança. Não é um teste de intrusão.

## 🔑 Chave da API, `.env`, backup e Docker

- **Chave:** `anhanga keygen` gera 256 bits aleatórios e grava `ANHANGA_API_KEY` em `./.env` (permissão `0600`,
  já no `.gitignore`); não sobrescreve sem `--force`. O servidor lê o `.env` ao iniciar (variáveis já definidas no
  ambiente têm precedência). A interface pede a chave uma vez por aba; nas chamadas use `Authorization: Bearer <chave>`.
  A chave só é obrigatória para escutar fora do loopback ou atrás de proxy.
- **`/docs`, `/redoc`, `/openapi.json`:** desligados por padrão; `ANHANGA_DOCS=1` os liga. **`/healthz`** só responde
  `{"status":"alive"}`. **`/metrics`** exige a chave; o botão da interface busca com ela.
- **Sem recursos externos:** a interface não carrega fontes do Google (usa as fontes do sistema).
- **Backup:** `anhanga backup destino.db` copia o banco de forma consistente (API de backup do SQLite; pode rodar com o
  servidor ativo), grava com `0600` e não sobrescreve sem `--force`. A retenção (`storage.retention_days`, padrão 14
  dias) já limita o tamanho. Agende o backup no cron do host.
- **Docker:** `docker build -t anhanga .` e
  `docker run -d -p 7890:7890 --env-file .env -v "$PWD/data:/data" anhanga` (coloque `targets.yaml` em `data/`; o diretório
  precisa ser gravável pelo uid 10001). Roda sem privilégios, tem `HEALTHCHECK` e **não inicia sem `ANHANGA_API_KEY`**.

## ✅ Validação cruzada com o testssl.sh

Protocolos (SSLv2 a TLS 1.3) comparados com o `testssl.sh` 3.2.5 em 14 hosts públicos (`example.com`, `github.com`,
`wikipedia.org`, `cloudflare.com`, `python.org`, `mozilla.org` e os `badssl.com` de TLS 1.0/1.1/1.2, RC4, 3DES, NULL,
RC4-MD5 e DH1024), em 2026-11-14:

- **Concordam** em TLS 1.0–1.3 em 9 dos 14 hosts.
- **`null.badssl.com`:** o Anhangá aceita TLS 1.0/1.1 (confirmado com `openssl s_client`, cifra `ECDHE-RSA-NULL-SHA`); o
  `testssl.sh` diz "not offered" porque seu teste por sockets não oferece cifras NULL por padrão.
- **`rc4.badssl.com`, `3des.badssl.com`, `rc4-md5.badssl.com`:** o `testssl.sh` as aceita; o Anhangá reporta
  `unknown` ("não foi possível determinar"), não "rejeitado": o OpenSSL local não oferece RC4 nem 3DES, e um
  `handshake_failure` sozinho não prova que o servidor recusou a versão (só `protocol_version` prova).
  Um OpenSSL com RC4/3DES (`local_ciphers_complete()`) volta a tratar `handshake_failure` como recusa.
- **SSLv2/SSLv3:** o Anhangá os reporta como `untestable` (o OpenSSL moderno os removeu); o `testssl.sh` os testa por
  sockets próprios. Hoje o `testssl.sh` é a referência para esses dois.
- **Fora desta comparação:** nota de segurança e lista de cifras (só protocolos foram comparados).

**Cobertura de cifras (validação com `testssl.sh`, com o OpenSSL embutido dele):** a lista de cifras TLS 1.2 do Anhangá
foi **idêntica** à do `testssl.sh` em `example.com` (20), `github.com` (14) e `tls-v1-2.badssl.com` (22). Diferenças
conhecidas, agora sinalizadas na interface e no CLI: (1) **TLS 1.3** lista só a suíte negociada (`ciphers_complete=false`),
porque suítes 1.3 não são selecionáveis por exclusão em Python; (2) **RC4/3DES/SEED** não são ofertáveis pelo OpenSSL
local, então um alvo que as aceite (ex.: `example.com` aceita 3DES em TLS 1.0) não as mostra e não dispara o achado de
cifra fraca. `legacy_ciphers_untested=true` avisa que a ausência delas não prova nada. Para testá-las de verdade,
use o `testssl.sh` ao lado.
