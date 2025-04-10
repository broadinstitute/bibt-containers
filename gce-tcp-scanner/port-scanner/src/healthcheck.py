from http.server import BaseHTTPRequestHandler, HTTPServer


class HealthHandler(BaseHTTPRequestHandler):
    ready = False  # Shared readiness flag

    def do_GET(self):
        if self.path == "/ready":
            self.send_response(200 if HealthHandler.ready else 503)
        elif self.path == "/health":
            self.send_response(200)
        else:
            self.send_response(404)
        self.end_headers()


def run_health_server():
    server = HTTPServer(("0.0.0.0", 8080), HealthHandler)
    server.serve_forever()


def set_ready(state: bool):
    HealthHandler.ready = state
