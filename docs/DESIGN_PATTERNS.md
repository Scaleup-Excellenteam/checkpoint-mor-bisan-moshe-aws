# Design patterns

The brief asks for two documented, implemented patterns with the problem each
solves, why it was chosen and its trade-off. The two primary patterns are
**Strategy with dependency injection** (the security pipeline) and
**Observer / publish-subscribe** (room routing). Two supporting patterns that the
code also relies on, **Repository** and **Adapter**, are described afterwards.

## 1. Strategy (with dependency injection) — the security pipeline

**Where:** `chat_system/security_contracts.py` defines the protocols
`DeterministicDLPChecker`, `RecipeClassifier`, `URLExtractor` and
`URLReputationChecker`. `chat_system/security_policy.py::SecurityPolicy` receives
one implementation of each in its constructor and calls only the protocol methods.
`server.py`'s lifespan injects the production strategies (`RuleDLPChecker`,
`OllamaRecipeClassifier`, `RegexURLExtractor`, `VirusTotalURLReputationChecker`);
tests inject fakes.

**Problem it solves.** Four people built four security modules in parallel, on
separate branches, in one day, and the server had to run with any subset of them
finished. Without a fixed interface each module would have leaked its own data
shapes into the server, and testing the policy would have required a live Ollama
model and a live VirusTotal key.

**Why this pattern.** Freezing the contracts first (`SecurityDecision`,
`MessageSecurityContext`, the four protocols and the score bands) let every owner
work against the same interface. `SecurityPolicy` composes the strategies in the
agreed order (rules → local model only for scores 30-99 → URL reputation) and maps
their decisions to final reason codes; it never imports a concrete module. The
server wires real strategies once at startup, while `tests/test_security_policy.py`
and `tests/test_security_integration.py` swap in controlled fakes, so the whole
decision flow, including fail-closed paths, is testable offline. Adding a fourth
check (say, an IP-reputation strategy for the Anti-Bot requirement) means one new
class and one constructor argument.

**Trade-off.** Indirection: to understand a decision you read the policy *and* the
concrete strategy, and the contracts file is deliberately hard to change (every
owner must agree). The synchronous protocol also forces the server to run the
strategies in worker threads rather than natively async, which is simpler for
module authors but costs a thread hop per message.

## 2. Observer / publish-subscribe — room routing

**Where:** `server.py`. Each WebSocket connection registers itself in
`app.state.clients` with its own state (`user`, `selected_room`, bounded `queue`,
`writer` task). `handle_send` publishes an accepted message by taking a snapshot of
the subscribers whose `selected_room` matches and who are still active members,
and enqueues the event for each. The `writer` task per connection drains that
queue to the socket. The browser (`static/app.js`) and the CLI (`client.py`) are
the observers on the client side: one reader dispatches `event` frames to the
message list and `response` frames to the pending request by id.

**Problem it solves.** Messages must reach exactly the members of the selected
room and nobody else, while dozens of sockets with different speeds are attached.
Having the sender write directly to every recipient socket would couple the
sender's latency to the slowest recipient and would make membership and selection
checks race with the writes.

**Why this pattern.** Subscription state (who is looking at which room) lives on
the server and is updated under the operations lock, so the recipient snapshot is
consistent. Publishing is decoupled from delivery by the per-connection queue:
the sender's request completes as soon as the message is stored and enqueued, and
each writer task delivers at its own pace. Room isolation, leave/rejoin and
reconnect all fall out of the subscription rules rather than special cases, and
the tests (`test_selected_room_routing`, `test_security_chat_and_names`) verify
that non-selected and non-member connections stay silent.

**Trade-off.** Delivery is at-most-once and in-memory: a queue that overflows
(slow consumer) disconnects that client, and a client that is offline gets nothing
pushed; it must use `history` to catch up. Bounded queues also mean the system
prefers dropping a slow reader over unbounded memory growth, which is right for a
chat but would be wrong for a system needing guaranteed delivery.

## 3. Repository — persistence (supporting)

**Where:** `chat_system/database.py` is the only module that speaks SQL. It
exposes intent-level functions (`create_user`, `join_group`, `leave_group`,
`save_message`, `get_room_history`, `is_active_member`) that return plain dicts.

**Problem / why.** The server, auth and tests need the same membership rules
(rejoin reactivates `left_at`, senders must be active members, deleted messages
are hidden) without duplicating SQL. Centralizing them lets each function run in
a short transaction on its own connection, which is what makes the calls safe to
run from worker threads.

**Trade-off.** Explicit SQL per operation and no ORM conveniences; adding a
field means touching schema, repository and callers. Accepted for a small,
auditable schema.

## 4. Adapter — external services behind the contracts (supporting)

**Where:** `chat_system/local_llm.py::OllamaRecipeClassifier` turns the Ollama
HTTP API into `RecipeClassifier.classify`; `chat_system/url_security.py::
VirusTotalURLReputationChecker` turns VirusTotal domain reports into
`URLReputationChecker.check`.

**Problem / why.** The policy must not know about HTTP status codes, JSON
schemas, API keys, cache TTLs or rate limits. Each adapter hides one vendor,
enforces its own timeouts and fail-closed rules, and can be replaced (another
model runtime, another reputation provider) without touching the policy.

**Trade-off.** Vendor quirks are encoded in one place, which is good, but the
adapters carry real complexity (cache, coalescing, cooldown after HTTP 429) that
must be tested with mock transports rather than the real service.
