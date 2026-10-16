# AGENTS.md — Governança Multi-Agente e Fluxo Gitflow do Projeto Anhangá

Este documento define a arquitetura organizacional de agentes especialistas, responsabilidades técnicas, padrões de qualidade e o fluxo estrito de governança **Gitflow** para o desenvolvimento e evolução do **Anhangá**.

---

## 1. Equipe de Agentes Especialistas

1. **Orquestrador de Agentes (`agents-orchestrator`)**
   - **Papel**: Líder do pipeline técnico e guardião do fluxo Gitflow.
   - **Responsabilidades**: Coordena fases de execução, gerencia branches isoladas por especialidade, conduz handoffs com contexto completo, exige revisão cruzada (Cross-Code-Review) e só autoriza merge na `main` mediante aprovação formal e suíte de testes verde do Testador.

2. **Engenheiro SRE (`sre-engineer`)**
   - **Papel**: Especialista em Confiabilidade, Observabilidade, SLIs/SLOs e Automação CI/CD.
   - **Responsabilidades**: Precisão estatística de latência (p50, p95, p99, jitter, conexão fria vs. reaproveitada), exportação OpenMetrics/Prometheus compatível com `blackbox_exporter`, CLI para pipelines de CI/CD (`anhanga check` com JSON/SARIF) e alertas via Webhooks (Slack, Teams, Telegram).

3. **Engenheiro Backend Python (`backend-engineer`)**
   - **Papel**: Especialista em Arquitetura Assíncrona (`asyncio`, `httpx`, `httpcore`, `FastAPI`, `Pydantic`).
   - **Responsabilidades**: Motor de sondagem de rede com medição exata por fase (DNS, TCP, TLS, TTFB/Processamento, Transferência), rastreamento hop-by-hop de cadeias de redirecionamento, inspeção profunda de certificados TLS (SANs, cadeia X.509, OCSP Stapling, detecção de TLS 1.0/1.1) e APIs de diagnóstico.

4. **Engenheiro de Segurança / DevSecOps (`security-engineer`)**
   - **Papel**: Especialista em AppSec, Defesa de Perímetro, Anti-SSRF e Hardening de Borda.
   - **Responsabilidades**: Proteção contra SSRF e DNS Rebinding (resolução única de DNS, bloqueio de IPs privados IPv4/IPv6/CGNAT/Link-Local/ULA/IPv4-mapped, socket IP pinning, revalidação a cada redirect), travas operacionais (rate limiting por cliente, timeouts rígidos, limite de payload), auditoria de cabeçalhos/cookies/CORS e Runbook de Remediação progressivo.

5. **Desenvolvedor Frontend (`frontend-developer`)**
   - **Papel**: Especialista em UI/UX Tática, Visualização de Dados, Acessibilidade (WCAG AA) e Internacionalização (PT-BR).
   - **Responsabilidades**: Dashboard com destaque para Security Grade e Latência Total, Waterfall tático com offset real e cores por SLO, tipografia semântica (`font-sans` para prosa, `font-mono` para dados/código), Runbook interativo multi-servidor (Nginx, Apache, Caddy, Traefik, K8s Ingress) com projeção simulada de nota, delta de re-scan, exportação (Permalink, JSON, Markdown) e cards com sparklines.

6. **Testador / QA (`qa-tester`)**
   - **Papel**: Especialista em Qualidade, Testes Automatizados (`pytest`) e Certificação Baseada em Evidências.
   - **Responsabilidades**: Validação rigorosa de cada fase em servidor local com latência controlada, testes de intrusão/bloqueio Anti-SSRF, validação de contratos Prometheus/SARIF/CLI e aprovação final (Quality Gate) antes de qualquer merge na `main`.

---

## 2. Governança Gitflow

### 2.1. Isolamento em Branches por Agente/Fase
Nenhum código de funcionalidade é desenvolvido diretamente na `main`. Cada fase/especialidade opera em sua própria branch isolada:
- `feat/phase1-waterfall-engine` — Engenheiro SRE & Engenheiro Backend Python
- `feat/phase2-anti-ssrf-security` — Engenheiro de Segurança (DevSecOps)
- `feat/phase3-ui-ux-redesign` — Desenvolvedor Frontend
- `feat/phase4-sre-cli-prometheus` — Engenheiro SRE & Engenheiro Backend Python
- `test/phase5-review-and-qa` — Testador & Revisão Cruzada

### 2.2. Commits Atômicos e Semânticos
Todos os commits devem ser atômicos e seguir o padrão **Conventional Commits**:
- `feat(<escopo>): ...`
- `fix(<escopo>): ...`
- `security(<escopo>): ...`
- `refactor(<escopo>): ...`
- `test(<escopo>): ...`
- `docs(<escopo>): ...`

### 2.3. Revisão Cruzada Obrigatória (Cross-Code-Review)
- As alterações de **Backend/SRE** (`probe.py`, `models.py`, `cli.py`, `main.py`) devem ser revisadas pelo **Engenheiro de Segurança** para garantir ausência de bypass de SSRF, vazamento de recursos ou injeção.
- As alterações de **Segurança** (`security.py`, guardrails, rate limiting, IP pinning) devem ser revisadas pelo **Engenheiro Backend** para garantir performance assíncrona, preservação de SNI/Host e estabilidade da API.

### 2.4. Quality Gate e Merge na `main`
- O merge para a branch `main` utiliza `git merge --no-ff` para preservar o histórico de governança das branches de cada agente.
- Nenhum merge definitivo na `main` é dado como concluído sem que 100% da suíte de testes unitários e de integração do **Testador** passe sem erros (`pytest`).
