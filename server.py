"""Terminal: runs shell sessions over localhost HTTP.

Runs on its own with `python3 server.py`. Any client can use it, a panel in Jarri is optional.

Endpoints (JSON unless noted):
  POST   /sessions                 {cols, rows, cwd?, command?} -> {id}
  POST   /sessions/{id}/input      raw bytes             -> 204
  POST   /sessions/{id}/resize     {cols, rows}          -> 204
  GET    /sessions/{id}/output?after=N                   -> {next, data (base64), exited}
  DELETE /sessions/{id}                                  -> 204

Security: binds to 127.0.0.1 only. Requests are accepted only when the Origin
and Host headers match an allowed list, so ordinary web pages in a browser
cannot drive a shell. A process running as the same user can still reach it.

Optional cwd (absolute, existing directory) and command (list of strings) start
the session in that directory running that command instead of a login shell.
The command runs through bash so PATH and aliases work. Without them the
session is a login shell, as before.
"""

import base64
import json
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import threading
import uuid
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import fcntl
import termios

HOST = "127.0.0.1"
PORT = int(os.environ.get("JARRI_TERMINAL_PORT", "8781"))
MAX_BUFFER = 1024 * 1024  # bytes kept per session for catch-up reads
ALLOWED_ORIGINS = {
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
    "http://localhost:1420",
    "http://127.0.0.1:1420",
    "http://localhost:8792",  # Jarri dev server (devUrl in tauri.conf.json)
    "http://127.0.0.1:8792",
}
ALLOWED_HOSTS = {f"{HOST}:{PORT}", f"localhost:{PORT}"}


class Session:
    def __init__(self, cols, rows, cwd=None, command=None):
        self.id = uuid.uuid4().hex
        self.lock = threading.Lock()
        self.chunks = []  # list of (offset, bytes)
        self.end = 0  # total bytes produced
        self.exited = False
        master, slave = pty.openpty()
        self.master = master
        self.resize(cols, rows)
        if command:
            argv = ["bash", "-ic", 'exec "$@"', "_", *command]
        else:
            argv = [os.environ.get("SHELL", "/bin/bash"), "-l"]
        self.proc = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=slave, stdout=slave, stderr=slave,
            start_new_session=True,
            env={**os.environ, "TERM": "xterm-256color"},
        )
        os.close(slave)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        while True:
            try:
                ready, _, _ = select.select([self.master], [], [], 0.5)
                if not ready:
                    if self.proc.poll() is not None:
                        break
                    continue
                data = os.read(self.master, 65536)
            except OSError:
                break
            if not data:
                break
            with self.lock:
                self.chunks.append((self.end, data))
                self.end += len(data)
                size = sum(len(c) for _, c in self.chunks)
                while size > MAX_BUFFER and len(self.chunks) > 1:
                    _, dropped = self.chunks.pop(0)
                    size -= len(dropped)
        with self.lock:
            self.exited = True

    def write(self, data):
        os.write(self.master, data)

    def resize(self, cols, rows):
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def read_after(self, after):
        with self.lock:
            start = max(after, self.chunks[0][0]) if self.chunks else self.end
            out = b"".join(c[max(0, start - off):] for off, c in self.chunks if off + len(c) > start)
            return {"next": self.end, "data": base64.b64encode(out).decode(), "exited": self.exited}

    def close(self):
        try:
            os.killpg(self.proc.pid, signal.SIGHUP)
        except OSError:
            pass
        try:
            os.close(self.master)
        except OSError:
            pass


SESSIONS = {}
SESSIONS_LOCK = threading.Lock()
SESSION_PATH = re.compile(r"^/sessions/([0-9a-f]{32})(/input|/resize|/output)?$")


class Handler(BaseHTTPRequestHandler):
    server_version = "jarri-terminal"

    def log_message(self, fmt, *args):
        pass

    def _allowed(self):
        origin = self.headers.get("Origin")
        if origin is not None and origin not in ALLOWED_ORIGINS:
            return False
        return self.headers.get("Host") in ALLOWED_HOSTS

    def _send(self, status, body=None):
        self.send_response(status)
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        if body is None:
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        raw = json.dumps(body).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _session(self, sid):
        with SESSIONS_LOCK:
            return SESSIONS.get(sid)

    def do_OPTIONS(self):
        if not self._allowed():
            return self._send(403, {"error": "forbidden origin"})
        self._send(204)

    def do_POST(self):
        if not self._allowed():
            return self._send(403, {"error": "forbidden origin"})
        path = urlparse(self.path).path
        if path == "/sessions":
            req = json.loads(self._body() or b"{}")
            cwd = req.get("cwd")
            command = req.get("command")
            if cwd is not None and not (isinstance(cwd, str) and os.path.isabs(cwd) and os.path.isdir(cwd)):
                return self._send(400, {"error": "cwd must be an existing absolute directory"})
            if command is not None and not (
                isinstance(command, list) and command and all(isinstance(arg, str) for arg in command)
            ):
                return self._send(400, {"error": "command must be a non-empty list of strings"})
            session = Session(int(req.get("cols", 80)), int(req.get("rows", 24)), cwd, command)
            with SESSIONS_LOCK:
                SESSIONS[session.id] = session
            return self._send(200, {"id": session.id})
        match = SESSION_PATH.match(path)
        if not match or not match.group(2):
            return self._send(404, {"error": "not found"})
        session = self._session(match.group(1))
        if session is None:
            return self._send(404, {"error": "no such session"})
        if match.group(2) == "/input":
            session.write(self._body())
            return self._send(204)
        if match.group(2) == "/resize":
            req = json.loads(self._body() or b"{}")
            session.resize(int(req["cols"]), int(req["rows"]))
            return self._send(204)
        return self._send(404, {"error": "not found"})

    def do_GET(self):
        if not self._allowed():
            return self._send(403, {"error": "forbidden origin"})
        parsed = urlparse(self.path)
        match = SESSION_PATH.match(parsed.path)
        if not match or match.group(2) != "/output":
            return self._send(404, {"error": "not found"})
        session = self._session(match.group(1))
        if session is None:
            return self._send(404, {"error": "no such session"})
        after = int(parse_qs(parsed.query).get("after", ["0"])[0])
        self._send(200, session.read_after(after))

    def do_DELETE(self):
        if not self._allowed():
            return self._send(403, {"error": "forbidden origin"})
        match = SESSION_PATH.match(urlparse(self.path).path)
        if not match or match.group(2):
            return self._send(404, {"error": "not found"})
        with SESSIONS_LOCK:
            session = SESSIONS.pop(match.group(1), None)
        if session is None:
            return self._send(404, {"error": "no such session"})
        session.close()
        self._send(204)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"terminal service on http://{HOST}:{PORT}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
