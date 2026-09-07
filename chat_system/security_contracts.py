"""Shared contracts for the chat security modules.

Freeze this file before parallel work. Changes require agreement from all owners.
"""

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, Sequence


SecurityAction = Literal["allow", "review", "block"]
SecuritySource = Literal["rules", "local_llm", "url_reputation", "policy"]
ProtectedField = Literal["message", "username", "room_name"]

ALLOW_MAX_SCORE = 29
REVIEW_MIN_SCORE = 30
HARD_BLOCK_SCORE = 100
CONTEXT_WINDOW_SIZE = 10


@dataclass(frozen=True)
class SecurityDecision:
    """One module's decision. details must never contain secrets or raw blocked text."""

    action: SecurityAction
    reason_code: str
    risk_score: int
    source: SecuritySource
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")


@dataclass(frozen=True)
class MessageSecurityContext:
    """Context for one attempted message; recent_attempts is oldest to newest."""

    user_id: int
    room_id: int
    recent_attempts: tuple[str, ...] = ()


class DeterministicDLPChecker(Protocol):
    def check(
        self,
        field_name: ProtectedField,
        text: str,
        context: MessageSecurityContext | None = None,
    ) -> SecurityDecision:
        """Return allow/review/block; hard forbidden variants return score 100."""


class RecipeClassifier(Protocol):
    def classify(self, text: str, recent_attempts: Sequence[str]) -> SecurityDecision:
        """Resolve rule scores 30-99 to allow or block using a local model."""


class URLExtractor(Protocol):
    def extract(self, text: str) -> list[str]:
        """Return normalized unique HTTP(S)/www URLs found in original text."""


class URLReputationChecker(Protocol):
    def check(self, url: str) -> SecurityDecision:
        """Return a cached or provider-backed URL reputation decision."""


class MessageSecurityPolicy(Protocol):
    def evaluate(self, text: str, context: MessageSecurityContext) -> SecurityDecision:
        """Combine DLP, optional local-LLM review, and URL reputation."""

