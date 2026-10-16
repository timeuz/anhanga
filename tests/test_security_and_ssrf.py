import asyncio
import unittest
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from anhanga.engine.models import TLSInspection
from anhanga.engine.probe import execute_probe
from anhanga.engine.security import (
    RATE_LIMITER,
    SlidingWindowRateLimiter,
    audit_http_security,
    is_ssrf_safe,
)
from anhanga.main import app


class TestSSRFAndDNSRebindingProtection(unittest.IsolatedAsyncioTestCase):
    def test_is_ssrf_safe_blocks_all_forbidden_ranges(self) -> None:
        forbidden_ips = [
            # Loopback IPv4 & IPv6
            "127.0.0.1",
            "127.0.53.53",
            "127.255.255.254",
            "::1",
            "[::1]",
            # RFC 1918
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.255.254",
            # Link-Local & Cloud Metadata (AWS/GCP/Azure/Alibaba)
            "169.254.169.254",
            "169.254.0.1",
            "fe80::1",
            "fe80::1%eth0",
            "[fe80::1%lo]",
            # CGNAT (RFC 6598 - 100.64.0.0/10)
            "100.64.0.1",
            "100.100.100.200",
            "100.127.255.254",
            # IPv6 ULA (RFC 4193 - fc00::/7)
            "fc00::1",
            "fd00::1",
            "fd12:3456:789a::1",
            # IPv4-mapped IPv6 bypass attempts
            "::ffff:127.0.0.1",
            "[::ffff:127.0.0.1]",
            "::ffff:10.0.0.1",
            "::ffff:172.16.0.1",
            "::ffff:192.168.1.1",
            "::ffff:169.254.169.254",
            "::ffff:100.64.0.1",
            # 6to4 (2002::/16) embedding 127.0.0.1 (7f00:0001) and 169.254.169.254 (a9fe:a9fe)
            "2002:7f00:0001::1",
            "2002:a9fe:a9fe::1",
            # Teredo (2001:0000::/32)
            "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
            # Unspecified, Broadcast, Multicast, Documentation
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "2001:db8::1",
            "ff02::1",
            # Invalid strings
            "",
            "not-an-ip",
        ]
        for ip in forbidden_ips:
            with self.subTest(ip=ip):
                self.assertFalse(
                    is_ssrf_safe(ip, allow_private=False),
                    f"IP {ip} deveria ser bloqueado pelo Guardião Anti-SSRF!",
                )

    def test_is_ssrf_safe_allows_public_ips(self) -> None:
        public_ips = [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "100.63.255.254",  # Fora do CGNAT
            "100.128.0.1",     # Fora do CGNAT
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ]
        for ip in public_ips:
            with self.subTest(ip=ip):
                self.assertTrue(
                    is_ssrf_safe(ip, allow_private=False),
                    f"IP público {ip} deveria ser permitido!",
                )

    async def test_execute_probe_rejects_forbidden_url_schemes(self) -> None:
        forbidden_urls = [
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "ftp://1.1.1.1/pub/file.txt",
            "dict://127.0.0.1:2628/",
            "javascript:alert(1)",
            "data:text/plain;base64,SGVsbG8=",
        ]
        for bad_url in forbidden_urls:
            with self.subTest(url=bad_url):
                res = await execute_probe(bad_url, allow_private=True)
                self.assertFalse(res.is_up)
                self.assertIsNotNone(res.error)
                self.assertIn("Anti-SSRF", res.error or "")

    async def test_redirect_to_forbidden_scheme_or_metadata_ip_is_blocked(self) -> None:
        async def _malicious_redirect_server(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                req_line = await reader.readline()
                path = req_line.decode("latin1").split(" ")[1] if req_line else "/"
                while True:
                    line = await reader.readline()
                    if not line or line in (b"\r\n", b"\n"):
                        break

                if path == "/to-gopher":
                    loc = "gopher://127.0.0.1:6379/_FLUSHALL"
                else:
                    loc = "http://169.254.169.254/latest/meta-data/"

                resp = (
                    "HTTP/1.1 302 Found\r\n"
                    f"Location: {loc}\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n\r\n"
                )
                writer.write(resp.encode("latin1"))
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(
            _malicious_redirect_server, "127.0.0.1", 0
        )
        port = server.sockets[0].getsockname()[1]
        try:
            # 1. Redirect para gopher:// é bloqueado mesmo com allow_private=True
            res_scheme = await execute_probe(
                f"http://127.0.0.1:{port}/to-gopher", allow_private=True
            )
            self.assertFalse(res_scheme.is_up)
            self.assertIn("esquema proibido", res_scheme.error or "")

            # 2. Redirect de um host público simulado para metadata IP (169.254.169.254) com allow_private=False
            orig_safe = is_ssrf_safe

            def _mock_safe_first_hop_only(ip_str: str, allow_private: bool = False) -> bool:
                if ip_str == "127.0.0.1":
                    return True
                return orig_safe(ip_str, allow_private)

            with patch(
                "anhanga.engine.probe.is_ssrf_safe", side_effect=_mock_safe_first_hop_only
            ):
                res_meta = await execute_probe(
                    f"http://127.0.0.1:{port}/to-metadata", allow_private=False
                )
                self.assertFalse(res_meta.is_up)
                self.assertEqual(res_meta.redirect_hops, 1)
                self.assertIn("Anti-SSRF", res_meta.error or "")
                self.assertEqual(res_meta.resolved_ip, "169.254.169.254")
        finally:
            server.close()
            await server.wait_closed()


class TestOperationalSafeguards(unittest.IsolatedAsyncioTestCase):
    async def test_payload_max_body_bytes_truncation(self) -> None:
        async def _large_payload_server(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                while True:
                    line = await reader.readline()
                    if not line or line in (b"\r\n", b"\n"):
                        break
                body = b"X" * 32768
                headers = (
                    "HTTP/1.1 200 OK\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Content-Type: text/plain\r\n"
                    "Connection: close\r\n\r\n"
                )
                writer.write(headers.encode("latin1") + body)
                await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(_large_payload_server, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            res = await execute_probe(
                f"http://127.0.0.1:{port}/big",
                allow_private=True,
                max_body_bytes=4096,
            )
            self.assertTrue(res.is_up)
            self.assertEqual(res.payload_bytes, 4096)
            self.assertTrue(res.payload_truncated)
        finally:
            server.close()
            await server.wait_closed()

    async def test_rigid_timeout_interrupts_tarpit_server(self) -> None:
        async def _tarpit_server(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                await asyncio.sleep(5.0)
            except Exception:
                pass
            finally:
                writer.close()

        server = await asyncio.start_server(_tarpit_server, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            res = await execute_probe(
                f"http://127.0.0.1:{port}/tarpit",
                timeout=0.6,
                allow_private=True,
            )
            self.assertFalse(res.is_up)
            self.assertIsNotNone(res.error)
            self.assertIn("Timeout", res.error or "")
        finally:
            server.close()
            await server.wait_closed()

    def test_rate_limiter_enforces_429_on_api(self) -> None:
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60.0)
        self.assertTrue(limiter.is_allowed("198.51.100.10"))
        self.assertTrue(limiter.is_allowed("198.51.100.10"))
        allowed, retry_after = limiter.check("198.51.100.10")
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry_after, 1)

        RATE_LIMITER.reset()
        RATE_LIMITER.max_requests = 2
        try:
            client = TestClient(app)
            r1 = client.get("/api/v1/scan?url=http://127.0.0.1:1")
            self.assertEqual(r1.status_code, 200)
            r2 = client.get("/api/v1/scan?url=http://127.0.0.1:1")
            self.assertEqual(r2.status_code, 200)
            r3 = client.get("/api/v1/scan?url=http://127.0.0.1:1")
            self.assertEqual(r3.status_code, 429)
            self.assertIn("Retry-After", r3.headers)
        finally:
            RATE_LIMITER.max_requests = None
            RATE_LIMITER.reset()


class TestSecurityRunbookAndHeadersAudit(unittest.TestCase):
    def setUp(self) -> None:
        self.valid_tls = TLSInspection(valid=True, protocol="TLSv1.3")

    def test_hsts_progressive_runbook_grants_max_score_without_preload(self) -> None:
        # 1. HSTS com max-age=2592000 (30 dias) SEM preload + CSP com frame-ancestors (sem X-Frame-Options!)
        headers = httpx.Headers(
            {
                "Strict-Transport-Security": "max-age=2592000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            }
        )
        audit = audit_http_security(headers, is_https=True, tls=self.valid_tls)
        self.assertEqual(audit.score, 100)
        self.assertEqual(audit.grade, "A+")
        self.assertFalse(audit.hsts_preload_opt_in)
        self.assertTrue(audit.hsts_include_subdomains)
        self.assertTrue(audit.csp_frame_ancestors)
        self.assertTrue(audit.permissions_camera_restricted)
        self.assertEqual(len(audit.missing_findings), 0)

        # 2. HSTS Etapa 1 (max-age=300): ganha 10 pts e gera finding de 15 pts com progressive_steps
        headers_stage1 = httpx.Headers(
            {
                "Strict-Transport-Security": "max-age=300",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=()",
            }
        )
        audit_s1 = audit_http_security(headers_stage1, is_https=True, tls=self.valid_tls)
        self.assertEqual(audit_s1.score, 85)
        self.assertEqual(audit_s1.grade, "A")
        self.assertEqual(len(audit_s1.missing_findings), 1)
        hsts_finding = audit_s1.missing_findings[0]
        self.assertEqual(hsts_finding.id, "SEC-HSTS")
        self.assertEqual(hsts_finding.weight, 15)
        self.assertEqual(len(hsts_finding.progressive_steps), 4)

    def test_permissions_policy_without_camera_deducts_5_pts(self) -> None:
        headers = httpx.Headers(
            {
                "Strict-Transport-Security": "max-age=2592000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=(), microphone=()",
            }
        )
        audit = audit_http_security(headers, is_https=True, tls=self.valid_tls)
        self.assertFalse(audit.permissions_camera_restricted)
        self.assertEqual(audit.score, 95)
        self.assertEqual(len(audit.missing_findings), 1)
        self.assertEqual(audit.missing_findings[0].header, "Permissions-Policy")
        self.assertEqual(audit.missing_findings[0].weight, 5)
        self.assertIn("camera=()", audit.missing_findings[0].description)

    def test_cookies_cors_and_leaks_findings_and_multi_server_snippets(self) -> None:
        headers = httpx.Headers(
            [
                ("Strict-Transport-Security", "max-age=2592000"),
                ("Content-Security-Policy", "default-src 'self'"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
                ("Permissions-Policy", "camera=()"),
                ("Set-Cookie", "sid=123; Path=/"),
                ("Access-Control-Allow-Origin", "*"),
                ("Server", "nginx/1.18.0"),
                ("X-Powered-By", "Express"),
            ]
        )
        audit = audit_http_security(headers, is_https=True, tls=self.valid_tls)
        self.assertTrue(audit.cors_wildcard)
        self.assertEqual(len(audit.cookies_audited), 1)
        self.assertEqual(len(audit.cookies_audited[0].issues), 3)
        self.assertEqual(len(audit.leaked_tech), 2)

        finding_ids = {f.id for f in audit.missing_findings}
        self.assertIn("SEC-XFO", finding_ids)
        self.assertIn("SEC-COOKIES", finding_ids)
        self.assertIn("SEC-CORS", finding_ids)
        self.assertIn("SEC-LEAK-SERVER", finding_ids)
        self.assertIn("SEC-LEAK-X-POWERED-BY", finding_ids)

        # Valida que todos os findings possuem os 5 snippets multi-servidor e que a soma fecha 100
        required_servers = {"nginx", "apache", "caddy", "traefik", "kubernetes"}
        for finding in audit.missing_findings:
            self.assertEqual(set(finding.snippets.keys()), required_servers)
            for srv, snippet in finding.snippets.items():
                self.assertTrue(bool(snippet.strip()), f"Snippet vazio para {srv}")

        projected_total = audit.score + sum(f.weight for f in audit.missing_findings)
        self.assertEqual(projected_total, 100)


if __name__ == "__main__":
    unittest.main()
