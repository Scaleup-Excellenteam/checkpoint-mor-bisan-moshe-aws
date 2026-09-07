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

## Security integration results (2026-09-07)

The original Person 4 baseline above is preserved. Integration started at main
`4db8863fc1d0395b0a660f0d844f91a356247602` and merged Person 1 `cc0514e`,
LLM `4cd967f`, URL `66c8bdf`, then reliability `b908b5a`, with no merge conflicts.
Production security integration is commit `40077fa` on `integration/security-system`.

Current test host: Windows 11 build 26200, Python 3.12.14, 8 logical CPUs.
CPU model/RAM were not measured; do not equate this with the original laptop.
All scenarios below use temporary databases, isolated loopback ports and synthetic
ordinary chat. The model/provider are not called by this low-score, URL-free load.

Commands (same workload before and after security wiring):

```powershell
./.venv/Scripts/python.exe scripts/load_test.py --clients 3 --messages 2
./.venv/Scripts/python.exe scripts/load_test.py --clients 8 --messages 10
```

| Stage | Clients / rounds | Success / attempted | Failures / unexpected disconnects | Elapsed s | Latency min / p50 / p95 / max ms |
| --- | --- | --- | --- | --- | --- |
| Merged modules, before wiring | 3 / 2 | 31 / 31 | 0 / 0 | 5.217 | 1.80 / 7.36 / 247.25 / 302.79 |
| Integrated, final run | 3 / 2 | 31 / 31 | 0 / 0 | 6.701 | 1.71 / 10.52 / 267.23 / 271.59 |
| Merged modules, before wiring | 8 / 10 | 67 / 67 | 0 / 0 | 8.749 | 2.01 / 16.61 / 371.16 / 394.09 |
| Integrated, final run | 8 / 10 | 67 / 67 | 0 / 0 | 8.884 | 1.68 / 17.94 / 267.35 / 317.38 |

The small/large scenarios verified 5/21 alpha messages, beta isolation, history,
leave/rejoin, reconnect and persistence after restart. These are single runs,
not statistical benchmarks. Bcrypt setup is included in request metrics and
process cleanup in elapsed time. Timing varies with host load and does not establish
security throughput, model latency, external provider latency or production capacity.
Only two clients send concurrently in this preserved harness; additional clients
connect and join. The larger workload is optional and is not added to normal pytest.

### Findings and fixes

- A Windows teardown failure appeared after otherwise successful assertions:
  `PermissionError` removing the temporary log. Stopping the venv launcher alone
  can leave its child holding files. The harness now stops only its known test-owned
  process tree on Windows, and waits for completion. Restricted sandboxes may need
  permission for `taskkill`. Cleanup failures are not ignored. The same cleanup
  helper is used by the existing subprocess chat tests.
- Concurrent completion order is not guaranteed once security checks run outside
  the shared lock. History assertions now compare exact message multiplicities
  rather than caller submission order; missing or duplicate acknowledged messages
  still fail. No production ordering guarantee was removed.
- The old CLI history assertion depended on where an asynchronous event inserted
  a newline relative to the prompt. It now checks timestamp + username + content,
  preserving the history-display check without scheduling-dependent line placement.
- Slow model/provider checks previously would have held a global policy lock.
  The policy now serializes by user/room. Server checks run outside its shared async
  lock and authorization/selection is rechecked before persistence.

### Security verification

Final full suite: **349 passed in 35.78 s**. Focused results: DLP/policy 117 passed,
local classifier 134 passed, URL module 66 passed, concurrency 1 passed. New security
integration tests: 10 passed in 21.59 s. Compile checks passed. Source/documentation whitespace checks passed; the inherited
`docs/reference/URL_SECURITY_INTEGRATION.patch` retains unified-diff context-marker spaces, which
Git flags as trailing whitespace. The historical patch is preserved unchanged.
The full suite includes real WebSocket servers and client/CLI flows; model/provider
responses are faked. No developer database or external credentials are needed.

```powershell
./.venv/Scripts/python.exe -m pytest -q tests/test_security_integration.py
./.venv/Scripts/python.exe scripts/security_smoke.py
```

The standalone smoke runs the real server subprocess, clients and both real
adapters against controlled loopback HTTP fixtures: 4 allowed messages, 5 blocked
cases (including names), 5 model HTTP calls, 3 provider HTTP calls, with selected-room
isolation and history/reconnect verified. Hard blocks skip the model; reviewed
content is resolved through the real adapter parser. Cached URLs avoid provider
calls and every extracted URL is evaluated before the final result.

Two integration cases pause a model or provider response with synchronization
events: another user sends successfully, `/health` responds within the two-second
test bound, and the original send remains pending. Leaving/rejoining from another
connection invalidates its selection; after release the pending send is rejected
and absent from history. These are controlled concurrency checks, not real-service
latency measurements.

Real Ollama/model verification: **not performed** (no installed runtime found).
Real VirusTotal verification: **not performed**; no API quota was consumed.
The team must install/configure the local model and supply provider credentials
for a manual service demo. Multi-laptop validation remains manual as described above.
