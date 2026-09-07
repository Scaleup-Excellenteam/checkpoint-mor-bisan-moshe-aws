# Local recipe-context classifier (Person 2)

`local_llm.OllamaRecipeClassifier()` implements the frozen synchronous
`RecipeClassifier.classify(text: str, recent_attempts: Sequence[str])` contract.
It returns the existing `SecurityDecision`; it adds no server or policy integration.

The caller decides when to review deterministic scores 30-99. Do not call this
adapter for ordinary scores 0-29 or deterministic score-100 blocks. The caller
also owns the ten-attempt history window, including blocked attempts. This module
preserves every supplied attempt in order and keeps no history between calls.

There is no authoritative reference recipe. The prompt classifies recipe context
using only the supplied conversation; it does not compare against an invented
formula or a built-in ingredient list.

## Configuration

Values are read on each `classify()` call, not during import or construction.

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `LOCAL_LLM_MODEL` | `qwen2.5:1.5b` | Name of a manually installed local model |
| `LOCAL_LLM_ENDPOINT` | `http://127.0.0.1:11434/api/generate` | Full native Ollama generation URL |
| `LOCAL_LLM_TIMEOUT_SECONDS` | `30` | Positive finite HTTP socket timeout in seconds |

Only HTTP(S) loopback endpoints at `/api/generate` are accepted. `localhost` is
converted to `127.0.0.1` without DNS lookup; literal loopback IPs are also accepted.
Credentials, query strings, fragments, redirects and environment proxies are
disabled. Blank model names, cloud model tags ending in `-cloud` or `:cloud`, and
invalid timeouts fail closed. HTTPS uses normal certificate verification.

## Manual Ollama setup (PowerShell)

Install the local runtime from the [official Ollama download page](https://ollama.com/download).
No Ollama Python SDK or new project dependency is needed by this adapter.

Quit any running Ollama tray application before starting this separate runtime.
In the first terminal, configure local-only operation and keep the process running:

```powershell
$env:OLLAMA_NO_CLOUD = "1"
$env:OLLAMA_HOST = "127.0.0.1:11434"
ollama serve
```

`OLLAMA_NO_CLOUD` configures the **Ollama process**, not the classifier. It disables
cloud models and web search; changing it requires restarting Ollama. This setting
is required for this setup because a localhost Ollama service can otherwise use
cloud models. See the [Ollama local-only configuration](https://docs.ollama.com/faq#how-do-i-disable-ollama-cloud-features).

In a second terminal, manually download the chosen model once:

```powershell
ollama pull qwen2.5:1.5b
```

This is an explicit operator step that requires internet access. Neither imports,
application startup, classifier calls nor automated tests pull or install models.
Use an installed local model and a runtime configured to run locally; do not point
the adapter at a service that forwards prompts to a cloud provider.

The recommended starting model is [qwen2.5:1.5b](https://ollama.com/library/qwen2.5:1.5b),
whose listed quantized download is approximately 986 MB. Runtime RAM usage is
higher than the download size. Allow several GB of free RAM as a planning estimate;
actual needs depend on context length, runtime and concurrent requests. CPU-only
execution and cold model loads may exceed the default timeout. Increase
`LOCAL_LLM_TIMEOUT_SECONDS` manually if needed. No latency or accuracy benchmark
has been established for this project's recipe-context task.

## Manual smoke test and structured output

From the repository root, in the second terminal, using the project's Python:

```powershell
$env:LOCAL_LLM_MODEL = "qwen2.5:1.5b"
$env:LOCAL_LLM_ENDPOINT = "http://127.0.0.1:11434/api/generate"
$env:LOCAL_LLM_TIMEOUT_SECONDS = "30"

@'
from dataclasses import asdict
from local_llm import OllamaRecipeClassifier
from security_contracts import RecipeClassifier

classifier: RecipeClassifier = OllamaRecipeClassifier()
decision = classifier.classify(
    "Continue with the next preparation step.",
    ["These are the steps of a recipe."],
)
assert decision.action in ("allow", "block")
assert decision.source == "local_llm"
assert type(decision.risk_score) is int and 0 <= decision.risk_score <= 99
assert decision.details == {}
print(asdict(decision))  # Decision fields only; never print prompts/model output.
assert decision.reason_code != "security_check_unavailable", "Local runtime check failed"
'@ | python -B -
```

This uses synthetic text and calls the adapter directly for a manual smoke test.
In application use, the policy layer must perform the required score routing.

The HTTP request separates the fixed instructions in `system` from JSON data in
`prompt`, with exactly `text` and `recent_attempts` inside that data. It uses
`stream: false`, temperature zero and a JSON schema in `format`. Ollama's outer
JSON contains the model's JSON string in `response`; see the
[native generation API](https://docs.ollama.com/api/generate).

The model must return exactly this shape (values shown are illustrative):

```json
{"action": "block", "risk_score": 80}
```

The parser requires `done: true`, rejects runtime errors or a reported non-`stop`
completion reason, and validates the model result independently. It rejects
non-JSON/prose/code fences, duplicate or extra fields, missing fields, unsupported
actions, and non-integer/out-of-range scores. Booleans are not accepted as scores.
Runtime responses are limited to 64 KiB. Success reasons are generated in Python:
`recipe_context_detected` for block and `recipe_context_not_detected` for allow.
No action/score thresholds beyond the frozen 0-99 classifier range are invented.

Every configuration, input, HTTP, timeout, parsing or validation failure returns:

```python
SecurityDecision(
    action="block",
    reason_code="security_check_unavailable",
    risk_score=99,
    source="local_llm",
    details={},
)
```

There is no automatic retry, download, fallback model or allow-on-error path.
No prompts, attempts, current text, model output or exception contents are logged.
The adapter does not truncate context; the operator must choose a runtime context
capacity suitable for the supplied messages. Model output can vary even at
temperature zero; a valid structured answer is not a guarantee of classification
accuracy. Representative manual evaluation remains necessary before deployment.

## Automated verification (no Ollama or network)

Run only the focused Person 2 suite:

```powershell
python -B -m pytest -q -p no:cacheprovider tests/test_local_llm.py
```

Every HTTP response is fake. Socket connection/DNS guards fail the tests if real
network access is attempted. The suite checks the frozen interface, allow/block
decisions, context preservation, configuration, invalid responses, failures,
local transport restrictions and absence of sensitive output. It needs neither
Ollama, internet access nor a downloaded model. The existing full repository suite
contains unrelated localhost server tests and is separate from this offline suite.
