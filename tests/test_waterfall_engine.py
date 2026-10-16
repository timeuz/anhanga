import asyncio
import os
import ssl
import subprocess
import tempfile
import unittest

from anhanga.engine.models import build_timing_breakdown
from anhanga.engine.probe import execute_probe


async def _handle_controlled_http(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    """
    Servidor HTTP/1.1 Keep-Alive minimalista com atrasos controlados:
    - /redirect -> responde em ~40ms com 302 Location: /final
    - /final    -> aguarda 120ms antes dos headers (TTFB) e transmite o body em 80ms (Transfer)
    """
    try:
        while True:
            request_line = await reader.readline()
            if not request_line:
                break
            parts = request_line.decode("latin1").strip().split(" ")
            path = parts[1] if len(parts) > 1 else "/"

            while True:
                line = await reader.readline()
                if not line or line in (b"\r\n", b"\n"):
                    break

            if path.startswith("/redirect"):
                await asyncio.sleep(0.040)  # 40ms TTFB no redirect hop
                resp_headers = (
                    "HTTP/1.1 302 Found\r\n"
                    "Location: /final\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: keep-alive\r\n"
                    "\r\n"
                )
                writer.write(resp_headers.encode("latin1"))
                await writer.drain()
                continue

            # Rota /final: 120ms de TTFB real
            await asyncio.sleep(0.120)
            chunk1 = b"A" * 2048
            chunk2 = b"B" * 2048
            total_len = len(chunk1) + len(chunk2)

            resp_headers = (
                "HTTP/1.1 200 OK\r\n"
                f"Content-Length: {total_len}\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: keep-alive\r\n"
                "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n"
                "Content-Security-Policy: default-src 'self'; frame-ancestors 'self'\r\n"
                "X-Content-Type-Options: nosniff\r\n"
                "X-Frame-Options: SAMEORIGIN\r\n"
                "Referrer-Policy: strict-origin-when-cross-origin\r\n"
                "Permissions-Policy: camera=(), geolocation=()\r\n"
                "Set-Cookie: session_id=xyz; Secure; HttpOnly; SameSite=Strict\r\n"
                "\r\n"
            )
            writer.write(resp_headers.encode("latin1"))
            writer.write(chunk1)
            await writer.drain()

            # 80ms de Transferência real entre o primeiro e o último bloco do body
            await asyncio.sleep(0.080)
            writer.write(chunk2)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def _generate_self_signed_cert(cert_path: str, key_path: str) -> None:
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "30",
            "-nodes",
            "-subj",
            "/C=BR/O=Anhanga Lab/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


class TestWaterfallEngine(unittest.IsolatedAsyncioTestCase):
    def test_build_timing_breakdown_offsets_and_slo(self) -> None:
        tb = build_timing_breakdown(
            dns_ms=12.5,
            tcp_ms=25.0,
            tls_ms=45.0,
            ttfb_ms=220.0,
            transfer_ms=30.5,
        )
        self.assertEqual(tb.total_ms, 333.0)
        self.assertEqual(tb.dominant_phase, "ttfb")
        self.assertEqual(len(tb.phases), 5)

        # Verifica offsets cumulativos sem sobreposição
        self.assertEqual(tb.phases[0].phase, "dns")
        self.assertEqual(tb.phases[0].start_ms, 0.0)
        self.assertEqual(tb.phases[0].end_ms, 12.5)
        self.assertFalse(tb.phases[0].is_dominant)

        self.assertEqual(tb.phases[3].phase, "ttfb")
        self.assertEqual(tb.phases[3].start_ms, 82.5)
        self.assertEqual(tb.phases[3].end_ms, 302.5)
        self.assertEqual(tb.phases[3].slo_status, "warning")
        self.assertTrue(tb.phases[3].is_dominant)

        self.assertEqual(tb.phases[4].phase, "transfer")
        self.assertEqual(tb.phases[4].start_ms, 302.5)
        self.assertEqual(tb.phases[4].end_ms, 333.0)

    async def test_controlled_latency_waterfall_and_warm_samples_http(self) -> None:
        server = await asyncio.start_server(
            _handle_controlled_http, "127.0.0.1", 0
        )
        port = server.sockets[0].getsockname()[1]

        try:
            url = f"http://127.0.0.1:{port}/final"
            res = await execute_probe(
                url, timeout=5.0, allow_private=True, samples=3
            )

            self.assertTrue(res.is_up, f"Probe failed with error: {res.error}")
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.payload_bytes, 4096)
            self.assertFalse(res.payload_truncated)

            # 1. Validação matemática da soma exata (sem multiplicador 0.4!)
            t = res.timings
            expected_sum = round(
                t.dns_ms + t.tcp_ms + t.tls_ms + t.ttfb_ms + t.transfer_ms, 2
            )
            self.assertEqual(t.total_ms, expected_sum)

            # 2. Validação da precisão de TTFB (~120ms) e Transfer (~80ms)
            self.assertGreaterEqual(t.ttfb_ms, 105.0)
            self.assertLessEqual(t.ttfb_ms, 175.0)
            self.assertGreaterEqual(t.transfer_ms, 65.0)
            self.assertLessEqual(t.transfer_ms, 135.0)

            # 3. Validação de Amostragem: Amostra 1 fria vs Amostras 2 e 3 quentes (reutilizadas)
            self.assertEqual(res.sampling.samples_count, 3)
            self.assertEqual(len(res.sampling.raw_samples), 3)

            s1, s2, s3 = res.sampling.raw_samples
            self.assertFalse(s1.connection_reused)
            self.assertTrue(s2.connection_reused)
            self.assertTrue(s3.connection_reused)

            self.assertEqual(s2.timings.dns_ms, 0.0)
            self.assertEqual(s2.timings.tcp_ms, 0.0)
            self.assertEqual(s2.timings.tls_ms, 0.0)
            self.assertEqual(s3.timings.tcp_ms, 0.0)
            self.assertIsNotNone(res.sampling.warm_avg_total_ms)
            self.assertIn("ttfb", res.sampling.phase_stats)
            self.assertIn("total", res.sampling.phase_stats)
        finally:
            server.close()
            await server.wait_closed()

    async def test_redirect_chain_and_tls_inspection_https(self) -> None:
        loop = asyncio.get_running_loop()
        orig_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda l, ctx: None)
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "cert.pem")
            key_path = os.path.join(tmpdir, "key.pem")
            _generate_self_signed_cert(cert_path, key_path)

            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

            server = await asyncio.start_server(
                _handle_controlled_http, "127.0.0.1", 0, ssl=ssl_ctx
            )
            port = server.sockets[0].getsockname()[1]

            try:
                url = f"https://127.0.0.1:{port}/redirect"
                res = await execute_probe(
                    url, timeout=5.0, allow_private=True, samples=2
                )

                self.assertTrue(res.is_up, f"HTTPS probe failed: {res.error}")
                self.assertEqual(res.redirect_hops, 1)
                self.assertEqual(len(res.redirect_chain), 1)

                hop = res.redirect_chain[0]
                self.assertEqual(hop.hop, 1)
                self.assertEqual(hop.status_code, 302)
                self.assertEqual(hop.location, "/final")
                self.assertGreaterEqual(hop.timings.ttfb_ms, 30.0)
                self.assertGreater(hop.timings.tls_ms, 0.0)

                # Verifica TLSInspection completa
                self.assertIsNotNone(res.tls)
                assert res.tls is not None
                self.assertTrue(res.tls.valid)
                self.assertIn(res.tls.protocol, ("TLSv1.2", "TLSv1.3"))
                self.assertFalse(res.tls.deprecated_protocol)
                self.assertIsNotNone(res.tls.cipher)
                self.assertIsNotNone(res.tls.cipher_bits)
                self.assertEqual(res.tls.issuer, "Anhanga Lab")
                self.assertEqual(res.tls.subject, "localhost")
                self.assertIsNotNone(res.tls.fingerprint_sha256)
                self.assertEqual(len(res.tls.fingerprint_sha256 or ""), 64)
                self.assertIn("localhost", res.tls.sans)
                self.assertIn("127.0.0.1", res.tls.sans)
                self.assertGreaterEqual(len(res.tls.cert_chain), 1)
                self.assertGreaterEqual(res.tls.days_remaining or 0, 28)

                # Verifica SecurityAudit no servidor HTTPS configurado com headers
                self.assertEqual(res.security.grade, "A+")
                self.assertEqual(res.security.score, 100)
                self.assertEqual(res.security.hsts_max_age, 63072000)
                self.assertTrue(res.security.hsts_include_subdomains)
                self.assertTrue(res.security.hsts_preload_opt_in)
                self.assertTrue(res.security.csp_frame_ancestors)
                self.assertTrue(res.security.permissions_camera_restricted)
                self.assertEqual(len(res.security.cookies_audited), 1)
                self.assertEqual(res.security.cookies_audited[0].name, "session_id")
            finally:
                server.close()
                await server.wait_closed()
                loop.set_exception_handler(orig_handler)

    async def test_ssrf_blocks_private_ip_when_not_allowed(self) -> None:
        res = await execute_probe("http://127.0.0.1:8080", allow_private=False)
        self.assertFalse(res.is_up)
        self.assertIsNotNone(res.error)
        self.assertIn("Anti-SSRF", res.error or "")


if __name__ == "__main__":
    unittest.main()
