#!/usr/bin/env python3
"""Simplified HTTP server with a thread-safe election state.

This file provides a minimal, easy-to-read implementation that keeps the
original behavior:

- GET /             -> plain text greeting
- GET /election/state -> JSON {"state": "open"|"closed"}
- POST /election/open  -> set state to "open" (text response)
- POST /election/close -> set state to "closed" (text response)
- POST /election/state -> set state via JSON payload {"state": "open"}

The original code used a subclass hook to inject endpoints; here we implement
the handler directly for clarity.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import signal
import sys
import json
import threading


class ElectionState:
    """Thread-safe storage for the election state.

    Only two values are allowed: "open" and "closed". Access is protected by
    a Lock so the state can be safely read/written from multiple threads.
    """

    def __init__(self, initial="closed"):
        self._state = initial
        self._lock = threading.Lock()

    def get(self):
        with self._lock:
            return self._state

    def set(self, value):
        if value not in ("open", "closed"):
            raise ValueError("invalid state")
        with self._lock:
            self._state = value


# Single global election state used by the handler
election = ElectionState()


# In-memory storage for voters, options and ballots
# - `voters`: map voter_id -> name
# - `options`: list of up to 4 location strings
# - `ballots`: list of dicts {"voter_id":..., "choice":...}
# Access to these structures should be thread-safe; reuse a lock used by
# ElectionState for simplicity (we can use a separate lock if desired).
voters = {}
options = ["Paris", "Rome", "Bahamas", "Lisbon"]
ballots = []
storage_lock = threading.Lock()


def send_json(handler, obj, status=200):
    """Send a JSON response using the provided request handler."""
    body = json.dumps(obj).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def send_text(handler, text, status=200):
    """Send a plain-text response using the provided request handler."""
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class reqHandler(BaseHTTPRequestHandler):
    """HTTP request handler with explicit api endpoints."""

    def do_GET(self):
        # Root greeting
        if self.path in ("/", "/index"):
            send_text(self, "Voting Server is running on port 5000\n", status=200)
            return

        # Return current election state as JSON
        if self.path == "/election/state":
            send_json(self, {"state": election.get()})
            return

        # Return list of registered voters
        if self.path == "/voters":
            # Return as list of {"voter_id": id, "name": name}
            with storage_lock:
                vlist = [{"voter_id": vid, "name": name} for vid, name in voters.items()]
            send_json(self, {"voters": vlist})
            return

        # Return configured options
        if self.path == "/options":
            with storage_lock:
                send_json(self, {"options": options})
            return

        # Return ballots only after the election has been closed
        if self.path == "/ballots":
            if election.get() != "closed":
                send_text(self, "ballots available only after election is closed\n", status=403)
                return
            with storage_lock:
                send_json(self, {"ballots": ballots})
            return

        # Fallback: not found
        send_text(self, "404 Not Found\n", status=404)

    def do_POST(self):
        # Registration endpoint: add a voter when election is closed (before opening)
        if self.path == "/register":
            if election.get() != "closed":
                send_text(self, "registration allowed only while election is closed\n", status=403)
                return

            length = int(self.headers.get("Content-Length", "0"))
            try:
                raw = self.rfile.read(length) if length else b""
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                send_text(self, "invalid JSON\n", status=400)
                return

            voter_id = payload.get("voter_id")
            name = payload.get("name")
            if not voter_id or not name:
                send_text(self, "missing voter_id or name\n", status=400)
                return

            with storage_lock:
                if voter_id in voters:
                    send_text(self, "voter already registered\n", status=409)
                    return
                voters[voter_id] = name

            send_json(self, {"voter_id": voter_id, "name": name}, status=201)
            return

        # Configure options (allowed only while election is closed)
        if self.path == "/options":
            if election.get() != "closed":
                send_text(self, "options may only be set while election is closed\n", status=403)
                return

            length = int(self.headers.get("Content-Length", "0"))
            try:
                raw = self.rfile.read(length) if length else b""
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                send_text(self, "invalid JSON\n", status=400)
                return

            opts = payload.get("options")
            if not isinstance(opts, list) or not opts or len(opts) > 4:
                send_text(self, "options must be a list of 1-4 values\n", status=400)
                return

            with storage_lock:
                options.clear()
                options.extend([str(o) for o in opts])

            send_json(self, {"options": options}, status=201)
            return

        # Submit a ballot: allowed only when election is open
        if self.path == "/vote":
            if election.get() != "open":
                send_text(self, "election is not open for voting\n", status=403)
                return

            length = int(self.headers.get("Content-Length", "0"))
            try:
                raw = self.rfile.read(length) if length else b""
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                send_text(self, "invalid JSON\n", status=400)
                return

            voter_id = payload.get("voter_id")
            choice = payload.get("choice")
            if not voter_id or choice is None:
                send_text(self, "missing voter_id or choice\n", status=400)
                return

            with storage_lock:
                if voter_id not in voters:
                    send_text(self, "Student not registered, speak to the Registrar,\n", status=403)
                    return
                # prevent double-voting: check if voter already in ballots
                if any(b.get("voter_id") == voter_id for b in ballots):
                    send_text(self, "You already voted, you are allowed to vote once for fairness\n", status=409)
                    return
                if choice not in options:
                    send_text(self, "invalid choice\n", status=400)
                    return

                ballots.append({"voter_id": voter_id, "choice": choice})

            send_text(self, "Ballot accepted\n", status=201)
            return

        # Open voting
        if self.path == "/election/open":
            election.set("open")
            send_text(self, "voting opened\n", status=200)
            return

        # Close voting
        if self.path == "/election/close":
            election.set("closed")
            send_text(self, "voting closed\n", status=200)
            return

        # Unknown POST endpoint
        send_text(self, "404 Not Found\n", status=404)

    def log_message(self, format, *args):
        # Route logs to stdout in a compact format (same as before).
        sys.stdout.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), format % args))


def run(host="127.0.0.1", port=5000):
    """Start the HTTP server and install a SIGINT handler for clean shutdown."""

    server = HTTPServer((host, port), reqHandler)
    print(f"Serving HTTP on http://{host}:{port} (Press CTRL+C to quit)")

    def handle_sigint(signum, frame):
        print("\nShutting down server")
        server.server_close()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)
    server.serve_forever()


if __name__ == "__main__":
    run()