# Anhangá 🦌🔥

> **Spectral Edge, TLS & Latency Auditor for SRE and DevSecOps**

O **Anhangá** é um motor de diagnóstico assíncrono de alta performance projetado para engenheiros de infraestrutura, SREs e DevSecOps que sabem que um `HTTP 200` isolado é frequentemente uma mentira.

Inspirado no guardião mitológico de olhos de fogo que vigia o perímetro, o Anhangá desce fundo na pilha de rede antes de aceitar que um endpoint está saudável.

---

## 🚀 O que ele audita?
1. **Decomposição de Latência em Tempo Real:** Separa o tempo exato gasto em **DNS**, **TCP Handshake**, **TLS Handshake**, **TTFB (Backend)** e **Transferência**.
2. **Auditoria DevSecOps de Borda:** Inspeção rigorosa de certificados SSL/TLS (dias restantes para expirar, versão do protocolo, cifra) e checagem de headers de segurança ausentes (`HSTS`, `CSP`, `X-Frame-Options`) com cálculo de *Security Grade (A+ até F)*.
3. **Proteção Anti-SSRF:** Bloqueia nativamente tentativas maliciosas de escanear redes internas ou metadados de nuvem (`169.254.169.254`).
4. **Observabilidade Nativa:** Expõe métricas detalhadas no formato OpenMetrics/Prometheus através da rota `/metrics`.

---

## 📦 Instalação e Execução com `uv`

```bash
# Cria o ambiente virtual e instala as dependências
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e .

# Sobe o servidor FastAPI na porta 7890
uvicorn anhanga.main:app --reload --host 127.0.0.1 --port 7890