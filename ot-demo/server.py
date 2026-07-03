#!/usr/bin/env python3
"""server.py — Local web server for the OT/ICS security demo.

Pure standard library (http.server + threads). Serves:
  GET  /                         -> the dashboard (index.html)
  GET  /api/stream?mode=<m>      -> Server-Sent Events: live plant snapshot ~2x/sec
  GET  /api/security?mode=<m>    -> the static threat-model / asset overlay (JSON)
  POST /api/attack/<k>?mode=<m>  -> inject an attack (setpoint_tamper|sensor_spoof|plc_stop)
  POST /api/clear?mode=<m>        -> clear all attacks, restore line

mode = 'automotive' (default) or 'building'.

Run:   python3 server.py            (defaults to http://127.0.0.1:8080)
       python3 server.py 0.0.0.0 8080   (bind all interfaces, e.g. on EC2)

Everything is a simulation. No real industrial device is contacted.
"""

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from sim_engine import PlantSim, security_model

HERE = os.path.dirname(os.path.abspath(__file__))
PLANTS = {
    "automotive": PlantSim("automotive"),
    "building": PlantSim("building"),
}
TICK_DT = 0.5   # seconds per simulation tick


def _sim_loop(plant):
    while True:
        plant.tick(TICK_DT)
        time.sleep(TICK_DT)


class Handler(BaseHTTPRequestHandler):
    # quieter logging
    def log_message(self, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass  # client disconnected

    # ── helpers ──────────────────────────────────────────────────────────────
    def _get_mode(self):
        qs = parse_qs(urlparse(self.path).query)
        mode = qs.get("mode", ["automotive"])[0]
        return mode if mode in PLANTS else "automotive"

    def _plant(self):
        return PLANTS[self._get_mode()]

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, ctype):
        try:
            with open(path, "rb") as f:
                body = f.read()
        except FileNotFoundError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── routes ───────────────────────────────────────────────────────────────
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            self._send_file(os.path.join(HERE, "index.html"), "text/html; charset=utf-8")
        elif path == "/api/security":
            self._send_json(security_model(self._plant()))
        elif path == "/api/stream":
            self._stream()
        else:
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path.startswith("/api/attack/"):
            kind = path.rsplit("/", 1)[-1]
            self._send_json(self._plant().inject_attack(kind))
        elif path == "/api/clear":
            self._send_json(self._plant().clear_attacks())
        else:
            self.send_error(404)

    # ── SSE stream ───────────────────────────────────────────────────────────
    def _stream(self):
        plant = self._plant()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            while True:
                payload = json.dumps(plant.snapshot())
                self.wfile.write(f"data: {payload}\n\n".encode())
                self.wfile.flush()
                time.sleep(TICK_DT)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return  # client navigated away


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

    for mode, plant in PLANTS.items():
        threading.Thread(target=_sim_loop, args=(plant,), daemon=True).start()

    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}"
    print("-" * 62)
    print("  OT/ICS Security Demo — Automotive + Smart Building")
    print("  Simulated plants + threat-model overlay (no real devices)")
    print("-" * 62)
    print(f"  Dashboard:  {url}")
    print("  Toggle mode in the top-right corner of the dashboard")
    if host == "0.0.0.0":
        print(f"  (bound to all interfaces - open http://<this-host-ip>:{port})")
    print("  Ctrl-C to stop.")
    print("-" * 62)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")


if __name__ == "__main__":
    main()
