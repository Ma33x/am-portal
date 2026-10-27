import http.client, json, tempfile, threading, unittest
from pathlib import Path
import server
from store import Store
from test_store import Fake


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        server.CONFIG = {
            "master_token": "m" * 48,
            "origin": "https://vpn.example.com",
            "admin_ips": ["192.0.2.1"],
        }
        server.store = Store(Path(self.tmp.name) / "test.sqlite", Fake())
        server.limits.clear()
        self.link = server.store.create("Test", 2)["token"]
        self.http = server.BoundedHTTPServer(("127.0.0.1", 0), server.Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()

    def request(
        self,
        path,
        token=None,
        data=None,
        ip="192.0.2.1",
        origin="https://vpn.example.com",
    ):
        c = http.client.HTTPConnection("127.0.0.1", self.http.server_port, timeout=5)
        headers = {"X-Real-IP": ip, "Origin": origin}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        body = None
        if data is not None:
            body = json.dumps(data)
            headers["Content-Type"] = "application/json"
        c.request(
            "POST" if data is not None else "GET", "/access/api/" + path, body, headers
        )
        r = c.getresponse()
        out = r.read()
        status = r.status
        c.close()
        return status, out

    def test_master_token_and_ip(self):
        self.assertEqual(self.request("master/list", self.link)[0], 403)
        self.assertEqual(self.request("master/list", "m" * 48, ip="192.0.2.2")[0], 403)
        self.assertEqual(self.request("master/list", "m" * 48)[0], 200)
        self.assertEqual(self.request("master/nested/list", "m" * 48)[0], 404)

    def test_public_link_and_bad_token(self):
        self.assertEqual(self.request("info", self.link, ip="192.0.2.2")[0], 200)
        self.assertEqual(self.request("info")[0], 401)
        self.assertEqual(self.request("info", "é" * 40)[0], 401)

    def test_origin(self):
        self.assertEqual(
            self.request("issue", self.link, {}, origin="https://evil.example")[0], 403
        )

    def test_qr_ownership(self):
        # Validation must reject someone else's text before invoking QR encoding.
        self.assertEqual(
            self.request("qr", self.link, {"text": "vpn://not-owned"})[0], 403
        )

    def test_wrong_admin_id(self):
        self.assertEqual(self.request("master/disable", "m" * 48, {"id": []})[0], 400)

    def test_bounded_rate_table(self):
        import time

        server.limits.update({str(i): (time.monotonic(), 1) for i in range(4096)})
        self.assertEqual(self.request("info", self.link)[0], 429)


if __name__ == "__main__":
    unittest.main()
