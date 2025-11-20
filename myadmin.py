import sys
import requests
from typing import Optional

#!/usr/bin/env python3
"""
myadmin.py

Simple admin client to open/close an election by sending HTTP requests
to a server running on localhost:5000.

Endpoints used (examples — adapt to your server API):
- POST /election/open        -> open the voting (no body required)
- POST /election/close       -> close the voting (no body required)
- GET  /election/state       -> query current voting state

Each function below documents the endpoint it uses.
"""


BASE_URL = "http://localhost:5000"
DEFAULT_TIMEOUT = 5.0


def _parse_response(resp):
    """Return parsed JSON when Content-Type is JSON, otherwise plain text.

    This helper makes the client tolerant of endpoints that return text
    (e.g. "voting opened\n") or JSON (e.g. {"state": "open"}).
    """
    ctype = resp.headers.get("Content-Type", "")
    if resp.content and "application/json" in ctype:
        try:
            return resp.json()
        except Exception:
            # malformed JSON -> fall back to text
            return resp.text
    # not JSON (or empty body) -> return text (or empty string)
    return resp.text if resp.content else {}


def open_election(timeout: float = DEFAULT_TIMEOUT) -> Optional[object]:
    """
    Open the election.

    Endpoint used:
    POST {BASE_URL}/election/open
    Purpose: instructs the server to transition the election into the 'open' state.

    Returns: parsed JSON response on success, None on failure.
    """
    url = f"{BASE_URL}/election/open"
    try:
        resp = requests.post(url, timeout=timeout)
        resp.raise_for_status()
        return _parse_response(resp)
    except Exception as e:
        print(f"open_election error: {e}")
        return None


def close_election(timeout: float = DEFAULT_TIMEOUT) -> Optional[object]:
    """
    Close the election.

    Endpoint used:
    POST {BASE_URL}/election/close
    Purpose: instructs the server to transition the election into the 'closed' state.

    Returns: parsed JSON response on success, None on failure.
    """
    url = f"{BASE_URL}/election/close"
    try:
        resp = requests.post(url, timeout=timeout)
        resp.raise_for_status()
        return _parse_response(resp)
    except Exception as e:
        print(f"close_election error: {e}")
        return None



def get_election_state(timeout: float = DEFAULT_TIMEOUT) -> Optional[object]:
    """
    Query the current election state.

    Endpoint used:
    GET {BASE_URL}/election/state
    Purpose: retrieve the current voting state (e.g. {"state": "open"}).

    Returns: parsed JSON response on success, None on failure.
    """
    url = f"{BASE_URL}/election/state"
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return _parse_response(resp)
    except Exception as e:
        print(f"get_election_state error: {e}")
        return None



def admin_main():
    print("You are now logged in as admin.")
    print("1. Open election")
    print("2. Close election")
    print("3. Check election status")
    print("4. exit")
    adminChoice = input("Please make a choice: ").strip() 

    if adminChoice == "1":
        result = open_election()
        print("open:", result)
    elif adminChoice == "2":
        result = close_election()
        print("close:", result)
    elif adminChoice == "3":
        result = get_election_state()
        print("status:", result)
    elif adminChoice == "4":
        return
    else:
        print("Invalid choice. Please try again.")
        return
    