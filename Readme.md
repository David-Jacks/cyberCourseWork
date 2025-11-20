# Simple Electronic Voting (Student Summer Location)

This small project provides an in-memory electronic voting system used by
students to select a summer vacation location. It's intentionally simple and
meant for demonstration / classroom use.

**Components**
- `myserver.py` — HTTP server that stores voters, options and ballots in memory, and exposes REST endpoints.
- `myadmin.py` — admin CLI to open and close the election.
- `myregistrar.py` — registrar CLI to register student voters and list options/voters.
- `myclient.py` — interactive CLI used by students to submit ballots while the election is open.
- `mytallier.py` — tallier CLI that retrieves ballots after the election is closed and prints results.

**Prerequisites**
- Python 3.8+ (or 3.7 should work)
- `requests` library installed (pip install requests)

Quick install (example):
```
python3 -m pip install --user requests
```

**Starting the system (server)**
1. Start the server on the machine that will host the election (default: `localhost:5000`):

```bash
python3 myserver.py
```

The server uses simple in-memory storage. If the process stops, all data (voters, options, ballots) is lost.

**Registrar (before opening the election)**
1. Configure the list of up to 4 locations (options) and register student voters before opening the election.
2. Run the registrar and follow prompts:

```bash
python3 myregistrar.py
# then choose: 1 to register a voter, 3 to view options, etc.
```

Registrar actions performed via HTTP on the server:
- `POST /options` — set options (allowed only while election is closed)
- `POST /register` — add a voter (allowed only while election is closed)

**Admin: open and close the election**
1. When setup is complete, an admin opens voting:

```bash
python3 myadmin.py
# choose Open election
```

2. After voting finishes, admin closes the election:

```bash
python3 myadmin.py
# choose Close election
```

Admin endpoints:
- `POST /election/open` — open voting
- `POST /election/close` — close voting
- `GET  /election/state` — check state

**Student voting (client)**
1. Students use the interactive client to vote while the election is open:

```bash
python3 myclient.py
```

2. The client will:
- Check that the election is `open`.
- Fetch current options (`GET /options`) and display them.
- Prompt for `Voter ID` and the choice (enter number shown or exact option name).
- Submit a ballot to `POST /vote`.

Important rules enforced by the server:
- Only registered voters may vote.
- Each voter may vote only once.
- Votes accepted only when election state is `open`.

**Tallier (after election closed)**
1. After admin closes the election, run the tallier to fetch ballots and compute counts:

```bash
python3 mytallier.py
```

The tallier uses `GET /ballots` (only available after the election is closed) and prints tallies and detailed ballots.

**Endpoints summary**
- `GET  /` — greeting
- `GET  /election/state` — current state `{ "state": "open"|"closed" }`
- `POST /election/open` — open voting
- `POST /election/close` — close voting
- `POST /register` — register voter (body: `{ "voter_id": "id", "name": "Name" }`) — only while closed
- `POST /options` — set options (body: `{ "options": [..] }`) — only while closed
- `GET  /voters` — list registered voters
- `GET  /options` — list current options
- `POST /vote` — submit ballot (body: `{ "voter_id": "id", "choice": "Option" }`) — only while open
- `GET  /ballots` — retrieve ballots (only after closed)

**Limitations & security notes**
- No persistence: everything is stored in memory and lost on restart.
- No authentication: the system trusts the provided `voter_id`. For real usage you must add authentication/tokens to prevent impersonation.
- Simple concurrency: server uses locks for in-memory structures but is not hardened for heavy production loads.
- Options are limited to a maximum of 4 locations (by design for this exercise).

**Recommended next steps / improvements**
- Add persistent storage (JSON file or SQLite) so votes survive restarts.
- Add per-voter authentication or signed tokens to prevent fraud.
- Add simple logging and export of results to CSV for record-keeping.

If you want, I can: start the server and run an end-to-end demo, add persistence, or add simple auth. Tell me which you prefer.

