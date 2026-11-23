"""
Proxmox VE Web Management UI Service (Port 8005)
Serves the Proxmox VE styled web interface and acts as reverse proxy for internal Node API.
"""
import os
import mimetypes
import logging
import urllib.request
import urllib.error
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from .config import cfg
from .cluster_auth import ensure_cluster_token

# Ensure font mimetypes
mimetypes.add_type("font/woff2", ".woff2")
mimetypes.add_type("font/woff", ".woff")
mimetypes.add_type("font/ttf", ".ttf")
mimetypes.add_type("application/vnd.ms-fontobject", ".eot")

logger = logging.getLogger("pve_gic_web")

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class WebUIHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def end_headers(self):
        # Force browser to never cache static CSS/JS/HTML during active management
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def log_message(self, format, *args):
        logger.debug(f"{self.client_address[0]} - {format % args}")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Node-Token, X-User-Session")
        self.end_headers()

    def proxy_to_api(self, method):
        """Forward /api requests to local 8004 API server, preserving cookies and sessions."""
        api_url = f"http://127.0.0.1:{cfg.api_port}{self.path}"
        headers = {
            "Content-Type": self.headers.get("Content-Type", "application/json")
        }

        # Forward cookies & headers
        if "Cookie" in self.headers:
            headers["Cookie"] = self.headers["Cookie"]
        if "X-User-Session" in self.headers:
            headers["X-User-Session"] = self.headers["X-User-Session"]
        if "X-Node-Token" in self.headers:
            headers["X-Node-Token"] = self.headers["X-Node-Token"]

        body_data = None
        if method in ["POST", "DELETE"]:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                body_data = self.rfile.read(content_length)

        req = urllib.request.Request(api_url, data=body_data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=120.0) as resp:
                resp_data = resp.read()
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    if k.lower() in ["content-type", "content-length", "set-cookie"]:
                        self.send_header(k, v)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(resp_data)
        except urllib.error.HTTPError as e:
            err_data = e.read()
            self.send_response(e.code)
            for k, v in e.headers.items():
                if k.lower() in ["content-type", "content-length", "set-cookie"]:
                    self.send_header(k, v)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(err_data)
        except Exception as e:
            err_msg = f'{{"error": "Failed to proxy request to local API on port {cfg.api_port}: {str(e)}"}}'.encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(err_msg)))
            self.end_headers()
            self.wfile.write(err_msg)

    def do_GET(self):
        if self.path.startswith("/api/"):
            return self.proxy_to_api("GET")

        # Dynamic server-side template rendering for index.html: inject detected PVE version
        clean_path = self.path.split("?")[0].rstrip("/")
        if clean_path in ["", "/index.html"]:
            index_file = os.path.join(STATIC_DIR, "index.html")
            try:
                with open(index_file, "r", encoding="utf-8") as f:
                    content = f.read()
                from .pve_scanner import scanner
                real_version = scanner.get_pve_version()
                content = content.replace("{{PVE_VERSION}}", real_version)
                encoded = content.encode("utf-8")

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
                return
            except Exception as e:
                logger.error(f"Error dynamically serving index.html: {e}")

        if self.path == "/" or self.path.strip() == "":
            self.path = "/index.html"

        return super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            return self.proxy_to_api("POST")
        self.send_error(405, "Method Not Allowed")

    def do_DELETE(self):
        if self.path.startswith("/api/"):
            return self.proxy_to_api("DELETE")
        self.send_error(405, "Method Not Allowed")

def run_web_server():
    server_address = (cfg.host, cfg.web_port)
    httpd = ThreadedHTTPServer(server_address, WebUIHandler)
    logger.info(f"PVE GIC Web UI running on http://{cfg.host}:{cfg.web_port}")
    httpd.serve_forever()
