# Anhangá

**Auditor de borda, TLS e latência para times de SRE e DevSecOps.**

[English](README.md)

O Anhangá é uma ferramenta assíncrona e auto-hospedada de diagnóstico e monitoramento de endpoints web. Um `HTTP 200` isolado raramente conta a história toda, então ele inspeciona o caminho completo da conexão: DNS, handshakes TCP e TLS, tempo até o primeiro byte, cadeia de redirecionamentos, estado do certificado e da revogação, suporte a protocolos e cifras, e a postura de segurança dos cabeçalhos da resposta. Roda como dashboard web com monitoramento contínuo, como CLI para quality gates de CI/CD e como alvo Prometheus compatível com os dashboards do `blackbox_exporter`.

**Status:** pré-lançamento (0.2.x). A suíte de testes é extensa, mas o projeto ainda não teve um soak longo nem uso real amplo. Veja [Limitações conhecidas](#limitações-conhecidas).

**Escopo:** o Anhangá foi desenhado para cada operador rodar na própria infraestrutura. Não é um serviço público ou multi-inquilino: tem uma única chave de API compartilhada, sem cotas por usuário e sem isolamento entre usuários. Também não é um teste de intrusão nem substitui uma ferramenta completa de avaliação TLS (veja [Validação](#validação)).

## Sumário

- [Recursos](#recursos)
- [Instalação](#instalação)
- [Início rápido](#início-rápido)
- [Configuração](#configuração)
- [Interface de linha de comando](#interface-de-linha-de-comando)
- [API HTTP](#api-http)
- [Integração com Prometheus](#integração-com-prometheus)
- [Alertas](#alertas)
- [Persistência](#persistência)
- [Modelo de segurança](#modelo-de-segurança)
- [Como ler os resultados](#como-ler-os-resultados)
- [Validação](#validação)
- [Limitações conhecidas](#limitações-conhecidas)
- [Desenvolvimento](#desenvolvimento)
- [Licença](#licença)

## Recursos

**Diagnóstico de latência**
- Tempos por fase (não acumulados) de DNS, TCP, TLS, TTFB e transferência, com offsets de início e fim e identificação automática da fase dominante.
- Sondagem com múltiplas amostras (até 20): P50, P95, P99, média, mín/máx e jitter, além da comparação entre conexão fria e conexão reaproveitada. O P95 só é informado com pelo menos 20 amostras e o P99 com pelo menos 100 (veja [percentis](#percentis)).
- Rastreamento da cadeia de redirecionamentos (301, 302, 303, 307, 308) com status, IP resolvido e latência por salto.

**Inspeção TLS**
- Validade do certificado, dias restantes, emissor, titular, número de série, fingerprint SHA-256, SANs e a cadeia X.509.
- Protocolo e cifra negociados, e estado do OCSP stapling.
- Verificação ativa de revogação (OCSP com CRL de fallback, assinaturas verificadas).
- Enumeração de protocolos e cifras (TLS 1.0 a 1.3) com achados para protocolos legados, cifras fracas e ausência de forward secrecy.

**Auditoria de segurança de borda**
- Nota de segurança de `A+` a `F` com base em HSTS, Content-Security-Policy (com análise de força), Permissions-Policy, X-Content-Type-Options, Referrer-Policy, flags de cookies, política de CORS e vazamento de versão de tecnologia.
- COOP, COEP e CORP são informativos e não afetam a nota.
- Runbook de remediação com snippets prontos para Nginx, Apache, Caddy, Traefik e Kubernetes Ingress, e um simulador de projeção de nota.

**Monitoramento e alertas**
- Sondagem contínua em segundo plano de uma lista de alvos, com sparklines, uptime e histórico de incidentes no dashboard.
- Alertas com estado (anti-flapping, deduplicação, lembretes, recuperação) enviados a Slack, Microsoft Teams ou Telegram, com outbox persistente de reenvio.

**Segurança**
- Proteção nativa contra SSRF e DNS rebinding; a conexão é fixada no IP validado.
- Autenticação da API que falha fechada e limitador de taxa.

## Instalação

Requer Python 3.11 ou superior e o binário `openssl` (usado para a cadeia de certificados, o OCSP stapling e a revogação; sem ele esses campos aparecem como "não verificado").

```bash
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e .
```

Com `pip` puro: `python -m venv .venv && . .venv/bin/activate && pip install -e .`

**Docker**

```bash
docker build -t anhanga .
docker run -d -p 7890:7890 --env-file .env -v "$PWD/data:/data" anhanga
```

Coloque o `targets.yaml` em `data/` (o diretório precisa ser gravável pelo uid 10001). O contêiner roda sem privilégios, tem `HEALTHCHECK` e se recusa a iniciar sem `ANHANGA_API_KEY`, porque escuta fora do loopback.

## Início rápido

```bash
anhanga serve                  # http://127.0.0.1:7890
```

- Dashboard (português e inglês): `http://127.0.0.1:7890`
- Health check: `GET /healthz`
- Documentação OpenAPI: desligada por padrão; defina `ANHANGA_DOCS=1` para habilitar `/docs`.

O dashboard executa scans sob demanda, simula correções, compara re-escaneamentos e exporta um link de análise compartilhável, JSON e Markdown. Atualiza sozinho a cada 15 segundos, filtra e ordena alvos por status e mostra uptime de 24 horas e incidentes recentes.

O `anhanga serve` sempre roda com um único worker. Cada worker executaria o próprio laço de monitoramento e duplicaria alertas, então não use `uvicorn --workers` nem `WEB_CONCURRENCY` maior que 1.

## Configuração

### `targets.yaml`

O Anhangá procura o `targets.yaml` no diretório de trabalho, ou no caminho de `ANHANGA_CONFIG`. Se `ANHANGA_CONFIG` estiver definida e o arquivo não existir, isso é um erro e nenhum outro arquivo é usado. Comece pelo exemplo:

```bash
cp targets.example.yaml targets.yaml
```

```yaml
interval_seconds: 30      # 5 a 86400; contado do início de cada ciclo
samples: 3                # 1 a 20 amostras por ciclo
allow_private: false      # true só para redes internas ou de laboratório

slo:                      # SLOs globais opcionais; cada alvo pode sobrescrever
  max_ttfb: 800ms
  max_total: 2s
min_grade: C              # alerta se a nota de segurança ficar abaixo

targets:
  - https://cloudflare.com
  - url: https://api.exemplo.com/health
    samples: 5
    slo: { max_ttfb: 300ms }
    min_grade: B

alerting:
  failure_threshold: 2    # ciclos ruins consecutivos antes de alertar
  recovery_threshold: 1
  cooldown_seconds: 3600  # intervalo entre lembretes; 0 desliga os lembretes
  notify_recovery: true

storage:
  enabled: true
  path: anhanga.db        # ANHANGA_DB_PATH sobrescreve
  retention_days: 14

webhooks:
  - url: "${SLACK_WEBHOOK_URL}"   # ${VAR} expande variáveis de ambiente
    provider: slack
  - url: "https://api.telegram.org/bot<TOKEN>/sendMessage"
    provider: telegram
    telegram_chat_id: "-1001234567890"
```

O arquivo é validado na carga: erros são registrados no log e entradas inválidas são descartadas em vez de parar o servidor. Ele é recarregado a quente quando muda; se o novo arquivo estiver ilegível ou com YAML inválido, a recarga é rejeitada e a configuração anterior continua valendo. Booleanos são estritos (`true/false`, `yes/no`, `on/off`, `1/0`); qualquer outro valor é um erro e cai no padrão seguro. Alvos são deduplicados pela URL normalizada (`example.com`, `https://example.com` e `HTTPS://EXAMPLE.COM` são o mesmo alvo). Hostnames internacionalizados são aceitos e convertidos para Punycode (IDNA 2008).

### Alvos adicionados pelo dashboard

O campo "Adicionar alvo" do dashboard grava alvos permanentes no SQLite (até 50) sem editar o `targets.yaml`. O botão "Remover", com confirmação em dois cliques, aparece só nesses cartões.

- Os alvos do `targets.yaml` continuam no arquivo, não são removíveis pela interface e vencem em caso de duplicata.
- Alvos do dashboard nunca usam `allow_private` (é decisão do operador, só no YAML). Loopback e endereços privados são recusados com 403 e não são gravados.
- Herdam o `slo` e o `min_grade` de topo.
- Endpoints: `GET`, `POST` e `DELETE /api/v1/targets/managed`. Exigem a chave de API como o resto de `/api/`, e o corpo do POST precisa ser JSON.
- O banco passa a fazer parte do seu estado: faça backup (veja [Persistência](#persistência)).

### Variáveis de ambiente

| Variável | Finalidade |
| --- | --- |
| `ANHANGA_API_KEY` | Chave da API. Obrigatória para escutar fora do loopback ou atrás de proxy reverso. |
| `ANHANGA_CONFIG` | Caminho do `targets.yaml`. |
| `ANHANGA_DB_PATH` | Caminho do banco SQLite (sobrescreve `storage.path`). |
| `ANHANGA_ENV_FILE` | Caminho do arquivo `.env` lido pelo servidor (padrão `./.env`). |
| `ANHANGA_ALLOW_PRIVATE` | `1` permite endereços privados nas rotas HTTP de scan (decisão do operador). |
| `ANHANGA_REVOCATION_CHECK` | `0` desliga as checagens OCSP/CRL. |
| `ANHANGA_REVOCATION_ALLOW_PRIVATE` | `1` permite que URLs de OCSP/CRL resolvam para endereços privados (PKI interna). |
| `ANHANGA_TLS_ENUM` | `0` desliga a enumeração de protocolos e cifras. |
| `ANHANGA_RATE_LIMIT_PER_MIN` | Limite de requisições por IP (padrão 30; `samples=N` custa N). |
| `ANHANGA_TRUSTED_PROXIES` | IPs de proxies cujo `X-Forwarded-For` é aceito (vazio por padrão). |
| `ANHANGA_SENSITIVE_COOKIE_REGEX` | Sobrescreve quais nomes de cookie exigem `HttpOnly`. |
| `ANHANGA_DOCS` | `1` habilita `/docs`, `/redoc` e `/openapi.json`. |
| `ANHANGA_PROBE_ORIGIN` | Rótulo do ponto de observação da sonda nos resultados. |

O `.env` é lido apenas pelas entradas do servidor (`anhanga serve`, `uvicorn anhanga.main:app`), nunca pelo `anhanga check`. Variáveis já definidas no ambiente têm precedência.

## Interface de linha de comando

```bash
anhanga serve [--host 127.0.0.1] [--port 7890]
anhanga check <url> [gates e opções]
anhanga keygen [--force]
anhanga backup <destino.db> [--force]
```

### `anhanga check`

Use em CI/CD (GitHub Actions, GitLab CI, Jenkins, Azure DevOps) para condicionar um deploy a critérios de desempenho e segurança.

```bash
# Nota mínima B, TTFB abaixo de 500 ms, 3 amostras
anhanga check https://exemplo.com --min-grade B --max-ttfb 500ms --samples 3

# Limita também a latência total
anhanga check https://api.exemplo.com --min-grade A --max-ttfb 300ms --max-total 1.5s

# JSON para scripts, SARIF para o GitHub Code Scanning
anhanga check https://exemplo.com --min-grade B --format json --output relatorio.json
anhanga check https://exemplo.com --min-grade A --format sarif --output anhanga.sarif

# Notifica um webhook quando um gate falha
anhanga check https://exemplo.com --min-grade B \
  --webhook-url "https://hooks.slack.com/services/T000/B000/X000" --webhook-provider slack
```

Opções: `--min-grade`, `--max-ttfb`, `--max-total`, `--samples/-n`, `--timeout/-t`, `--allow-private`, `--allow-invalid-cert`, `--format/-f {text,json,sarif}`, `--output/-o`, `--webhook-url`, `--webhook-provider {auto,slack,teams,telegram}`, `--telegram-chat-id`.

O `--max-ttfb` usa a mediana das amostras e o `--max-total` a latência de destaque, as mesmas funções que o monitor usa nos SLOs.

| Código de saída | Significado |
| :---: | --- |
| `0` | Todas as verificações passaram. |
| `1` | Alvo offline, certificado TLS inválido (exceto com `--allow-invalid-cert`), TTFB ou latência total acima do limite, ou asserção de conteúdo falhou. |
| `2` | Nota de segurança abaixo de `--min-grade`. |
| `3` | Erro de DNS, bloqueio SSRF, alvo inválido, ou argumentos ou configuração inválidos. |

Em um `check` de execução única, o bloco de protocolos e cifras TLS pode aparecer como "não avaliado", porque a enumeração termina em segundo plano; nunca aparece como "sem protocolos".

### `keygen` e `backup`

O `anhanga keygen` gera 256 bits aleatórios e grava `ANHANGA_API_KEY` em `./.env` com permissão `0600`. Não sobrescreve uma chave existente sem `--force`.

O `anhanga backup` faz uma cópia consistente do banco com a API de backup do SQLite. Pode rodar com o servidor ativo, grava com permissão `0600`, expande `~` e não sobrescreve sem `--force`. Agende no cron do host.

## API HTTP

Todas as rotas sob `/api/`, mais `/probe` e `/metrics`, exigem a chave de API. O `/healthz` e o HTML do dashboard são abertos; os dados em cache só são embutidos na página para clientes autorizados.

| Rota | Descrição |
| --- | --- |
| `GET /api/v1/scan?url=&samples=&timeout=` | Diagnóstico sob demanda de qualquer URL (o botão de scan do dashboard). Aceita asserções de conteúdo. Não é armazenado. |
| `GET /api/v1/targets` | Último estado conhecido de todos os alvos monitorados. |
| `GET/POST/DELETE /api/v1/targets/managed` | Alvos adicionados pelo dashboard. |
| `GET /api/v1/history?target=&hours=24&max_points=300` | Série agregada: checks, up/degraded/down e latência média/mín/máx por bucket. |
| `GET /api/v1/uptime[?target=]` | `uptime_pct` (saúde up) e `availability_pct` (HTTP respondeu) em 24 h, 7 d e 30 d, com a cobertura real dos dados. |
| `GET /api/v1/incidents[?target=&open_only=true&limit=]` | Incidentes abertos e encerrados, com duração. |
| `POST /api/v1/webhooks/notify` | Envia um alerta gerado pelo servidor a um webhook declarado no `targets.yaml`. |
| `GET /probe?target=&samples=` | Sondagem sob demanda no estilo multi-target do `blackbox_exporter`. |
| `GET /metrics` | Métricas Prometheus dos alvos monitorados. |

Falhas em que o alvo não respondeu retornam erros estruturados: `400` URL inválida, `403` bloqueio SSRF, `502` falha de DNS, conexão ou TLS, `504` timeout, com `{"detail": {"error_code", "message", "target_url"}}`. Achados sobre um alvo que respondeu (5xx, asserção reprovada, TLS inválido) continuam `200`.

## Integração com Prometheus

As durações são exportadas em segundos. Além das séries estendidas `anhanga_probe_*`, são exportadas as séries padrão do `blackbox_exporter` (`probe_success`, `probe_duration_seconds`, `probe_http_duration_seconds{phase="resolve|connect|tls|processing|transfer"}`, `probe_http_status_code`, `probe_http_ssl`, `probe_ssl_earliest_cert_expiry`), então dashboards Grafana existentes podem ser reaproveitados. O `probe_success` vale `1` apenas quando a saúde é `up`.

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

O `anhanga_probe_latency_quantile_seconds` sempre traz a mediana (`quantile="0.5"`); as séries `0.95` e `0.99` só são exportadas quando o ciclo tem amostras suficientes (pelo menos 20 e 100, respectivamente), a mesma regra do dashboard e do CLI, e são removidas caso contrário. As mensagens de alerta e o export em Markdown seguem a mesma regra. Para a latência de cauda ao longo do tempo, use o `anhanga_probe_duration_seconds_histogram` com `histogram_quantile()`.

Alvos que não responderam não exportam séries de latência, nota ou TLS (sem zeros falsos). O contador `anhanga_assertions_not_evaluated_total{target}` incrementa quando o próprio avaliador de regex falha; alerte em `rate(...) > 0`, senão uma falha persistente do avaliador desativa as asserções de regex em silêncio.

## Alertas

- **Gatilhos:** alvo offline, TLS inválido, certificado expirando, violação de SLO de TTFB ou de latência total (mediana quando `samples >= 2`) e nota abaixo de `min_grade`. SLOs e nota podem ser definidos por alvo.
- **Anti-flapping:** um problema só notifica após `failure_threshold` ciclos consecutivos (padrão 2).
- **Deduplicação:** uma notificação, depois um lembrete apenas após `cooldown_seconds` (padrão 1 hora).
- **Recuperação:** uma notificação quando o problema some.
- **Limiar de expiração do certificado:** o menor entre 15 dias e 20% da vida do certificado, então certificados de vida curta não ficam "expirando" o tempo todo. Um certificado expirando que expira ou é revogado escala para `degraded` sem a mensagem verde de "resolvido".
- **Entrega:** em paralelo e em segundo plano, então um webhook lento nunca atrasa as sondagens. Uma entrega só conta com resposta 2xx. Falhas têm duas novas tentativas, depois entram numa outbox persistente e são reenviadas com backoff (30 s, 2 min, 10 min, 30 min, 1 h), descartadas após cerca de 1 hora de tentativas ou 24 horas de idade. Métricas: `anhanga_alert_notifications_total{kind,result}` e `anhanga_alert_outbox_pending`.
- **Provedores** são detectados pelo hostname (`api.telegram.org`; `office.com`, `outlook.com`, `logic.azure.com`, `teams.microsoft.com` e subdomínios); qualquer outro é tratado como compatível com Slack. Os limites de mensagem são respeitados sobre o texto já escapado (cabeçalho do Slack 150 caracteres, bloco de violações 3000; Telegram 4096), cortando por linha com "(+N omitidas)" e mantendo sempre a primeira violação.
- **Desligamento:** entregas em andamento ganham 5 segundos; o restante vai para a outbox.

## Persistência

SQLite (biblioteca padrão, sem dependência extra). Fica ativo quando há alvos, ou quando o arquivo do banco já existe. O arquivo padrão é `anhanga.db` no diretório de trabalho.

O que fica salvo: histórico de sondagens (sparklines e uptime sobrevivem a reinícios), estado dos alertas (sem alerta duplicado após reiniciar, cooldown respeitado), incidentes, a outbox de notificações e os alvos adicionados pelo dashboard. O arquivo é criado com permissão `0600`, e a outbox guarda apenas um hash de cada URL de webhook (o segredo fica só na configuração). Uma falha de disco nunca para o monitoramento: é registrada e contada em `anhanga_storage_errors_total`.

O histórico mais antigo que `retention_days` (padrão 14) é podado a cada hora, e o arquivo encolhe por vacuum incremental em blocos (bancos criados com `auto_vacuum=INCREMENTAL`). Uma estimativa grosseira é de 150 bytes por sondagem: 10 alvos a cada 30 segundos dão cerca de 130 MB em 30 dias.

Faça backup com `anhanga backup`, ou `sqlite3 anhanga.db ".backup out.db"`.

## Modelo de segurança

- **Autenticação:** com `ANHANGA_API_KEY` definida, envie `Authorization: Bearer <chave>` ou `X-API-Key`. Sem chave, só é aceito acesso direto por loopback: o cabeçalho `Host` precisa ser um nome de loopback e `X-Forwarded-For`, `Forwarded` e `X-Real-IP` precisam estar ausentes, então um proxy reverso na mesma máquina é tratado como externo. O `anhanga serve` recusa iniciar em endereço fora do loopback sem chave.
- **SSRF:** bloqueia loopback, RFC 1918, link-local e metadados de nuvem (`169.254.0.0/16`, `fe80::/10`), CGNAT, IPv6 ULA e formas tuneladas ou mapeadas (`::ffff:127.0.0.1`, 6to4, Teredo), além de esquemas não HTTP. A conexão TCP é fixada na única resposta DNS validada, e o endereço é revalidado a cada redirecionamento. `allow_private` e `ANHANGA_ALLOW_PRIVATE` são exclusivos do operador; não existe parâmetro de query para isso.
- **URLs vindas do certificado:** as URLs de OCSP, CRL e AIA vêm do certificado do alvo, que é entrada de terceiros. Passam pela mesma política SSRF, não herdam o `allow_private` do alvo, têm limite de tamanho (OCSP 64 KB, CRL 3 MB) e de tempo. PKI interna exige `ANHANGA_REVOCATION_ALLOW_PRIVATE=1` explícito.
- **Webhooks:** `POST /api/v1/webhooks/notify` só envia para URLs declaradas no `targets.yaml`, o corpo do alerta é sempre montado pelo servidor, e um `provider` ou `chat_id` diferente do configurado é recusado.
- **Asserções de regex** rodam num subprocesso isolado com timeout de 2 s e padrão limitado a 512 caracteres (proteção contra ReDoS).
- **Processo:** a imagem Docker roda sem privilégios. O `/healthz` retorna apenas `{"status":"alive"}`. A interface não carrega recursos externos (fontes do sistema, Alpine e Tailwind embutidos).
- **Revisão:** uma leitura automatizada do código (subprocessos, SSRF, autenticação, SQL, XSS, YAML) não encontrou vulnerabilidade de alta confiança. Não é um teste de intrusão.

Não exponha `/probe` e `/api/v1/scan` sem chave: eles conectam a hosts escolhidos por quem chama.

## Como ler os resultados

### Saúde

`health` é `up` (HTTP ok e TLS válido), `degraded` (HTTP ok mas TLS inválido: expirado, hostname divergente, raiz não confiável, revogado) ou `down`. O motivo exato está em `tls.validation_error`. Os dias restantes do certificado podem ser negativos (expirou há N dias).

### Tempos

DNS, TCP, TLS, TTFB e transferência são durações por fase, não acumuladas. O `curl -w` reporta tempos acumulados (`time_connect`, `time_appconnect`, `time_starttransfer`); para comparar, subtraia a fase anterior. O `server_processing_ms` só é calculado a partir de amostras de TTFB confiáveis (quentes); o TTFB frio em HTTP/2 pode incluir cerca de 1 RTT extra, e com `samples=1` o campo é `null`. O `end_to_end_ms` inclui todos os redirecionamentos. Os percentis de DNS, TCP e TLS usam apenas amostras com conexão nova. Se uma amostra quente falhar, a primeira é mantida, as seguintes são puladas e o fato fica em `timings.timing_notes`; o alvo só fica offline se a primeira amostra falhar.

### Percentis

O P95 exige pelo menos 20 amostras e o P99 pelo menos 100, porque abaixo disso não têm significado estatístico. Um scan ou ciclo de monitoramento é limitado a 20 amostras (para não sobrecarregar o alvo), então o dashboard mostra o P95 apenas com a opção 20x e nunca mostra o P99. Para a latência de cauda ao longo do tempo, use o histograma exportado em `/metrics` com `histogram_quantile()` no Prometheus. Veja também [Limitações conhecidas](#limitações-conhecidas).

### Orçamento de tempo

As etapas depois da resposta HTTP (cadeia TLS e OCSP stapling, porta 80, enumeração de protocolos, TLS legado, revogação, CORS, regex) têm cada uma o seu prazo. Se uma estourar, as etapas já concluídas são mantidas e o resultado sai parcial (anotado em `timings.timing_notes`; o regex vira `assertions.not_evaluated`) em vez de descartar um 200 válido como timeout. As asserções definitivas (`assert_final_url`, `max_payload_bytes`) são avaliadas antes da etapa de regex para nunca se perderem. Uma resposta que o servidor envia mas nunca encerra (visto em `www.gnu.org`, onde o `curl` também trava) excede o prazo total e é reportada como offline; esse é o comportamento do alvo.

### Protocolos e cifras TLS

Cada sondagem HTTPS enumera, com handshakes restritos a cada versão, quais protocolos (TLS 1.0 a 1.3) e cifras o servidor aceita. As cifras de TLS 1.2 e anteriores são descobertas por exclusão iterativa (no máximo 24 handshakes por versão). A enumeração nunca segura uma sondagem por mais de 3 segundos; se o alvo aceita muitas cifras, ela termina em segundo plano e o resultado aparece a partir do ciclo seguinte, em cache por `hostname:porta` por 6 horas (15 minutos se algum estado foi inconclusivo). No máximo uma nova enumeração por `ip:porta` a cada 2 minutos. Na primeira sondagem de um alvo o bloco pode vir como "não avaliado".

Estados: `accepted`; `rejected` (só conta um alerta TLS do servidor: um `handshake_failure` isolado não prova que a versão foi recusada, só o `protocol_version` prova); `unknown` (timeout, falha de rede ou limitação do cliente; nunca tratado como recusado nem guardado em cache como conclusivo); e `untestable` (SSLv2 e SSLv3, removidos do OpenSSL moderno).

Achados: `SEC-TLS-LEGACY` (TLS 1.0 ou 1.1 aceito), `SEC-TLS-WEAK-CIPHER` (NULL, anônimas, RC4, DES, 3DES, EXPORT, MD5) e `SEC-TLS-NO-PFS` (troca de chaves RSA estática). Protocolos legados ou cifras fracas limitam a dimensão de transporte da nota a 10/40, e a falta de PFS desconta 5 pontos. Se a checagem de TLS 1.0 e 1.1 não pôde ser concluída, o dashboard mostra "Não verificado" e a nota não concede o bônus de TLS moderno: não verificado não é o mesmo que seguro. Quando um handshake falha por completo, o erro diz o que o servidor aceita (por exemplo "aceita apenas TLSv1").

### Revogação

O OCSP é verificado ativamente (a assinatura da resposta é conferida contra o emissor), com CRL como fallback (assinatura e `nextUpdate` conferidos). O `tls.revocation.status` é `good`, `revoked`, `unknown`, `unavailable` ou `error`. Revogado implica `tls.valid=false`, `health=degraded`, `probe_success=0`, gate do CLI reprovado e um alerta. "Indisponível" nunca é reportado como "não revogado". O Let's Encrypt encerrou o OCSP, então para ele só o CRL pega a revogação.

Os resultados ficam em cache (bom 30 min, revogado 1 h, falhas 5 min, CRLs até o `nextUpdate` ou 6 h). Uma checagem de revogação nunca segura uma sondagem por mais de 4 segundos e não é cancelada: um CRL lento termina em segundo plano (teto de 25 s) e o ciclo seguinte lê o cache. No máximo 4 checagens em segundo plano simultâneas e 32 na fila. A checagem só roda enquanto o certificado ainda é válido.

### Content-Security-Policy

O `security.csp_analysis` classifica a política como `strong`, `moderate`, `weak` ou `report-only` e lista as causas: `'unsafe-inline'` sem nonce ou hash, `'unsafe-eval'`, curingas, `http:`, `data:`, `https:` genérico, `script-src` ou `default-src` ausentes, `object-src` diferente de `'none'`, `base-uri` ausente e hosts que permitem bypass (JSONP, CDNs). Nonces, hashes e `'strict-dynamic'` são reconhecidos. Várias políticas são conjuntivas: uma política sem `script-src` ou `default-src` não esconde o `'unsafe-inline'` de outra. Uma política Report-Only não conta como proteção. A pontuação da CSP é proporcional à qualidade (forte 100%, moderada 80%, fraca 50%) e uma política fraca gera `SEC-CSP-WEAK` com um snippet mais rígido.

### Cabeçalhos de isolamento de origem cruzada

COOP, COEP e CORP são lidos da resposta HTTPS. A ausência de COOP ou COEP gera achados informativos `SEC-COOP` e `SEC-COEP` com peso 0 (endurecimento opcional; o COEP quebra embeds de terceiros sem CORP ou CORS). Um valor inválido, que o navegador ignora, é `low`. `unsafe-none` conta como ausente. A ausência de CORP não é apontada, já que só se aplica a recursos.

### Heurísticas

`Server:` só é vazamento se expõe versão. `HttpOnly` só é exigido de cookies de sessão e autenticação; os nomes de token de double-submit (`csrftoken`, `XSRF-TOKEN`, `X-CSRF-TOKEN`, `csrf_token`, aceitando `__Host-`, `__Secure-` e `_` inicial) não precisam dele porque o JavaScript tem de lê-los, enquanto `_csrf` (o segredo do csurf) continua sensível. O `error_code` é `tls_error` apenas para marcadores reais de TLS, nunca porque um hostname por acaso contém um.

## Validação

O suporte a protocolos (SSLv2 a TLS 1.3) foi comparado com o `testssl.sh` 3.2.5 em 14 hosts públicos (`example.com`, `github.com`, `wikipedia.org`, `cloudflare.com`, `python.org`, `mozilla.org` e os hosts `badssl.com` de TLS 1.0, 1.1, 1.2, RC4, 3DES, NULL, RC4-MD5 e DH1024) em 2026-11-14.

- As duas ferramentas concordam em TLS 1.0 a 1.3 em 9 dos 14 hosts.
- `null.badssl.com`: o Anhangá reporta TLS 1.0 e 1.1 aceitos (confirmado com `openssl s_client`, cifra `ECDHE-RSA-NULL-SHA`); o `testssl.sh` diz "not offered" porque seu teste por sockets não oferece cifras NULL por padrão.
- `rc4.badssl.com`, `3des.badssl.com`, `rc4-md5.badssl.com`: o `testssl.sh` as encontra aceitas, enquanto o Anhangá reporta `unknown` em vez de "rejeitado", porque o OpenSSL local não oferece RC4 nem 3DES e um `handshake_failure` isolado não prova recusa.
- SSLv2 e SSLv3 são reportados como `untestable`; o `testssl.sh` é a referência para esses dois.
- Nesta rodada só os protocolos foram comparados, não a nota.

A cobertura de cifras foi verificada com o `testssl.sh` usando o OpenSSL embutido dele: a lista de cifras TLS 1.2 foi idêntica em `example.com` (20 cifras), `github.com` (14) e `tls-v1-2.badssl.com` (22). Duas diferenças conhecidas são sinalizadas na interface e no CLI. O TLS 1.3 lista apenas a suíte negociada (`ciphers_complete=false`), porque suítes TLS 1.3 não podem ser selecionadas por exclusão a partir do Python. RC4, 3DES e SEED não podem ser ofertadas pelo OpenSSL local, então um alvo que as aceite não as mostra e não dispara o achado de cifra fraca; `legacy_ciphers_untested=true` avisa que a ausência delas não prova nada. Para uma resposta definitiva sobre essas, use o `testssl.sh` ao lado.

## Limitações conhecidas

- **Não validado contra serviços reais:** os payloads de webhook são testados contra mocks e limites de tamanho; a entrega real para Slack, Microsoft Teams e Telegram não foi exercitada de ponta a ponta.
- **Sem soak longo ainda:** uma execução de 14 minutos contra 12 alvos mostrou memória estável (cerca de 125 MB) e nenhum processo `openssl` órfão. O comportamento ao longo de dias não foi verificado.
- **Sem P99 no dashboard nem nas métricas por ciclo:** veja [Percentis](#percentis). Use o histograma para a latência de cauda.
- **Enumeração TLS:** o OpenSSL local não testa RC4, 3DES, EXPORT nem SSLv3 (veja [Validação](#validação)). "Rejeitado" significa "recusou todas as cifras que este cliente oferece".
- **Cadeia de certificados atrás de balanceadores:** se a folha da cadeia difere do certificado da conexão (renovação no meio da sondagem, ou certificados diferentes por backend), a cadeia é descartada como "não verificado", então a revogação pode ficar indisponível de forma intermitente atrás desses balanceadores. Quando a fila do `s_client` está cheia o resultado é indistinguível de uma falha do `openssl`, então sob carga a cadeia pode aparecer "não verificada" de forma intermitente.
- **Desligamento:** quem aguarda uma checagem de revogação cancelada recebe `CancelledError`; isso só ocorre ao encerrar.
- **Baixos, sem correção:** a mesclagem manual de `ContentAssertionsResult` no `probe.py` é frágil a campos novos; o auxiliar de IDNA descarta a porta `0` e marcadores `?` ou `#` vazios; a folga de 50 ms que distingue "prazo esgotado" de "timeout da etapa" é uma heurística.
- **Instância única:** um worker e um processo; não há clusterização.
- **Fora do primeiro lançamento:** auditoria de DNS e e-mail (CAA, SPF, DMARC, DNSSEC), refatoração do layout do dashboard e integração com o SSL Labs. Veja o `BACKLOG.md`.

## A fazer

- **Validar a entrega real de webhooks.** Os payloads de Slack, Microsoft Teams e Telegram são cobertos por testes contra mocks e limites de tamanho, mas uma mensagem real ainda não foi entregue a cada serviço de ponta a ponta.
- Itens de prazo mais longo (auditoria de DNS e e-mail, refatoração do layout do dashboard, integração com o SSL Labs) estão no `BACKLOG.md`.

## Desenvolvimento

```bash
uv pip install -e ".[dev]"
pytest
```

A suíte (cerca de 500 testes) roda offline, exceto por fixtures de PKI local (uma CA real, CRL e respondedor OCSP, `s_server`), e leva cerca de um minuto. O CI a executa em Python 3.11, 3.12 e 3.13. Os testes de regressão são escritos para falhar sem a correção e verificados com teste de mutação.

## Licença

MIT. Veja o arquivo [LICENSE](LICENSE).
