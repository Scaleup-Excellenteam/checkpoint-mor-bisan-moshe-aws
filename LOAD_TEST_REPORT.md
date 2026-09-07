# Load Test Report

## Baseline

This report records the baseline for the authenticated WebSocket chat server at
the shared-contracts commit (`4db8863`). The harness is verification tooling,
not a capacity benchmark and does not establish production limits.

Run the quick deterministic check with:

```powershell
py -m pytest -q tests/test_concurrency.py
```

Run the manually invoked local scenario with configurable workload:

```powershell
py scripts/load_test.py --clients 3 --messages 2
py scripts/load_test.py --clients 8 --messages 10
```

Each run creates a temporary database and log, chooses a free loopback port,
starts a controlled `server.py` subprocess, waits for `/health`, and terminates
the subprocess during cleanup. The developer's `chat.db` is never used.

## Coverage

The scenario creates unique accounts, signs up and logs in every client,
creates and joins rooms, selects and leaves rooms, rejoins, sends concurrently,
checks selected-room isolation, reconnects, verifies history persistence,
restarts the server against the same temporary database, checks `/health`, and
verifies clean shutdown. It compares every acknowledged message with received
room events and fails on duplicates, missing messages, or unexpected events.

The output includes attempted, successful and failed operation counts,
unexpected disconnects, elapsed time, and min/p50/p95/max request latency.
The default workload is intentionally small for student laptops.

## Baseline Results

Environment: Windows, ASUS VivoBook X512FJ, 8 logical processors, 7.9 GB RAM,
Python 3.12.3. Workload: 3 clients and 2 messages per concurrent sender round.

Command: `py scripts/load_test.py --clients 3 --messages 2`

Observed result: 31 attempted, 31 successful, 0 failed operations, 0
unexpected disconnects, 6.546 seconds elapsed, and latency min/p50/p95/max of
2.56/12.00/432.04/554.78 ms. Five alpha messages were verified and beta room
isolation passed. The focused test passed (`1 passed in 7.97s`), and the full
suite passed (`22 passed in 23.45s`).

Observed limits: this local scenario is suitable for regression detection only.
It does not measure production capacity, LAN behavior, WAN behavior, or the
maximum supported number of clients.

## Defects and Reproduction

No baseline production defect was fixed by this owner. If a run fails, retain
the JSON output and temporary server log, then record the command and whether
the failure is baseline or introduced by security integration. Do not silently
adjust assertions to hide a regression.

## Post-Integration Comparison

After final DLP and URL integration, run the same commands with the same client
and message counts. Compare operation failures, unexpected disconnects,
latency percentiles, message delivery, room isolation, persistence, and clean
shutdown. A changed result is a regression candidate, not a production-capacity
claim.

## Multi-Laptop Checklist

1. Start the server on the host laptop with its LAN address and a test port.
2. Confirm the host firewall allows that TCP port on the private network.
3. From each other laptop, open the WebSocket client using the host LAN IP,
   not `127.0.0.1`, and use unique test accounts.
4. Exercise two rooms, concurrent sends, leave/rejoin, and reconnect manually.
5. Confirm clients in the other room receive no live events and compare server
   logs with client output.
6. Stop the server and remove test data after the run.

Automated loopback load does not prove LAN connectivity or firewall behavior.