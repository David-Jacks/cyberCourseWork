#!/usr/bin/env python3
"""End-to-end test script for the voting system.

This script starts the actual HTTP server implemented in myserver.py
and runs the election phases in sequence:
    - register voters
    - open election
    - cast votes
    - close election
    - tally votes

It verifies that ballots are recorded and included in the final tally.
"""

import os
import json
import time
import pathlib
import re
import io
from http.server import HTTPServer
import threading
import requests
import myserver
from my_utils import DEFAULT_HOST, _maybe_load_keys_env, hash_id
from myregistrar import add_voter
from myadmin import close_election, open_election
from myclient import check_state, get_options, submit_ballot
from mytallier import tally_and_print
from contextlib import redirect_stdout


def _sanitize_tally_output(s: str) -> str:
    """Replace raw Python byte-repr fragments like ``b'...''`` with a concise
    placeholder and truncate very long lines for readability.
    """
    # Replace byte reprs with an estimated size placeholder. Use DOTALL
    # non-greedy matches to capture the entire b'...'/b"..." fragments.
    def _blob_repl(m):
        inner = m.group(1)
        # estimate bytes by counting '\x' escapes if present
        esc_count = len(re.findall(r"\\x[0-9A-Fa-f]{2}", inner))
        approx = esc_count if esc_count > 0 else len(inner)
        return f"<binary blob ~{approx} bytes>"

    s2 = re.sub(r"b'(.*?)'", _blob_repl, s, flags=re.DOTALL)
    s2 = re.sub(r'b"(.*?)"', _blob_repl, s2, flags=re.DOTALL)

    # Truncate extremely long lines to keep test output readable
    out_lines = []
    for line in s2.splitlines():
        if len(line) > 500:
            out_lines.append(line[:500] + "...<truncated>")
        else:
            out_lines.append(line)
    s_final = "\n".join(out_lines)
    # Collapse long runs of hex-escaped bytes like '\xHH\xHH...' left behind
    s_final = re.sub(r'(?:\\x[0-9A-Fa-f]{2}){3,}', '<binary-escapes>', s_final)
    return s_final


def start_server():
    """Start the real HTTP server in a background thread."""
    _maybe_load_keys_env()
    repo_root = pathlib.Path(__file__).parent
    db_path = repo_root / "my_db.JSON"
    if db_path.exists():
        os.environ.setdefault("STUDENT_DB_FILE", str(db_path))
    server = HTTPServer(("127.0.0.1", 5000), myserver.reqHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    return server


def stop_server(server):
    try:
        server.shutdown()
    except Exception:
        pass
    try:
        server.server_close()
    except Exception:
        pass


def print_stage(title):
    print("\n" + "=" * 10 + f" {title} " + "=" * 10)


def verify_registered_voters(expected_ids):
    print("Verifying registered voters...")
    
    url = DEFAULT_HOST + "/voters"
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        voters = resp.json().get("voters", [])
        hashed_ids = [v.get("voter_hash") for v in voters]
        for eid in expected_ids:
            if eid not in hashed_ids:
                print(f"  ERROR: Voter {eid} not registered!")
            else:
                print(f"  Voter {eid} registered.")
    except Exception as e:
        print(f"  ERROR: Could not verify voters: {e}")


def verify_ballots(expected_count):
    print("Verifying ballots...")
    url = DEFAULT_HOST + "/ballots"
    try:
        resp = requests.get(url, timeout=5)
        # If the server returns a non-200 status (e.g., 403 while election
        # is still open), print the server-provided text message rather
        # than raising an exception with the numeric status.
        if resp.status_code != 200:
            text = resp.text.strip() if resp.text else f"HTTP {resp.status_code}"
            print(f"  Server response: {text}")
            return
        ballots = resp.json().get("ballots", [])
        if len(ballots) == expected_count:
            print(f"  All {expected_count} ballots recorded.")
        else:
            print(f"  ERROR: Expected {expected_count} ballots, found {len(ballots)}.")
    except Exception as e:
        print(f"  ERROR: Could not verify ballots: {e}")


def run_election_flow():
    server = start_server()
    try:
        # 1. Register voters
        print_stage("Register Voters")
        repo_root = pathlib.Path(__file__).parent
        db_path = repo_root / "my_db.JSON"
        if db_path.exists():
            with db_path.open("r", encoding="utf-8") as f:
                j = json.load(f)
                students = [(s.get("id"), s.get("name")) for s in j.get("students", [])][:7]
        else:
            students = [
                ("50534358", "Chloe Martinez"),
                ("54763679", "Daniel Kim"),
                ("51660641", "Eva López"),
                ("07555595", "Frank Wilson"),
                ("99660550", "Alice Johnson"),
                ("99308237", "Ben Carter"),
                ("12345678", "Grace Hopper"),
            ]

        # Keep any short secrets returned (printed) by the registrar so we
        # can supply them non-interactively to the voting client.
        secret_re = re.compile(r"your secret ticket for voting is: (\d+)")
        short_secrets = {}
        for sid, name in students:
            print(f"Registering {name} (ID: {sid})...")
            buf = io.StringIO()
            # Capture registrar printed output to extract the short secret
            try:
                with redirect_stdout(buf):
                    add_voter(sid, name)
            except Exception:
                # If registrar raised, still try to use any captured text
                pass
            out = buf.getvalue()
            match = secret_re.search(out)
            if match:
                short_secrets[sid] = match.group(1)
            else:
                # No secret printed (server may not be configured for Schnorr);
                # leave absent so submit_ballot will run without proof.
                short_secrets[sid] = None
            # Also echo the registrar output to the test runner console
            print(out.strip())

        # Verify registration
        hashed_ids = [hash_id(sid) for sid, _ in students]
        verify_registered_voters(hashed_ids)

        # 2. Open election
        print_stage("Open Election")
        open_election()
        state = check_state()
        print(f"Election state: {state}")

        # 3. Print options
        print_stage("Available Options")
        options = get_options()
        print(f"Options: {options}")

        # 4. Accept votes
        print_stage("Voting Phase")
        # To create a clear winner for tests, prepare a deterministic
        # vote plan of 7 votes where 'Bahamas' receives the majority (4 votes).
        vote_choices = [
            "Bahamas", "Bahamas", "Bahamas", "Bahamas",  # 4 votes for Bahamas
            "Paris", "Rome", "Lisbon",  # remaining votes
        ]
        for idx, (sid, name) in enumerate(students):
            # Prefer an explicit vote from our vote plan when available.
            if idx < len(vote_choices):
                choice = vote_choices[idx]
            else:
                choice = options[idx % len(options)] if options else None
            if not choice:
                print("  ERROR: No voting options available")
                continue
            print(f"{name} (ID: {sid}) voting for {choice}...")
            # Supply the short secret captured at registration to avoid any
            # interactive prompts inside the client. If no secret was
            # captured, pass None and the client will skip including a Schnorr proof.
            voter_secret = short_secrets.get(sid)
            status, text = submit_ballot(sid, choice, voter_secret=voter_secret)
            print(f"  Server response: {status} {text}")

        # Verify ballots
        verify_ballots(len(students))

        # 5. Close election
        print_stage("Close Election")
        close_election()
        state = check_state()
        print(f"Election state: {state}")

        # 6. Tally votes
        print_stage("Tally Votes & Output Result")
        # Call the existing tally_and_print() but capture its stdout so the
        # test runner can examine or reprint it without modifying the module.
        tbuf = io.StringIO()
        try:
            with redirect_stdout(tbuf):
                result = tally_and_print()
        except Exception as e:
            result = None
            print(f"  ERROR running tally: {e}")

        # Print the captured tally output for the test run but sanitize it
        # to avoid dumping large raw binary blobs into test logs.
        tally_out = tbuf.getvalue()
        clean = _sanitize_tally_output(tally_out)
        if clean.strip():
            print(clean)

        # Also print the structured result returned by the tallier (if any)
        # in a clear, machine-readable form so tests can assert on it.
        print("result = ", end="")
        if result is None:
            print("None")
        else:
            # Pretty-print the dict with sorted keys for deterministic output
            import pprint
            pp = pprint.pformat(result, width=120, sort_dicts=True)
            print(pp)

    finally:
        stop_server(server)
        print("\nElection test complete. Server stopped.")


if __name__ == "__main__":
    run_election_flow()