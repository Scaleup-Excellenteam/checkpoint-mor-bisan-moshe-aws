"""Human-readable explanations for protocol error and security reason codes.

Single source of truth shared by the CLI (``cli.py``), the Web UI (served through
``GET /api/reasons``) and the documentation. Codes are stable strings; the text
here is display-only and never influences a security decision.
"""

SECURITY_REASONS: dict[str, dict[str, str]] = {
    "forbidden_term": {
        "control": "DLP",
        "title": "Protected term blocked",
        "explanation": "The message or name contains the protected term (pineapple) or a disguised "
                       "variant of it (typo, leetspeak, homoglyph, separators). Deterministic rule, "
                       "score 100, blocked before any model or provider call.",
    },
    "recipe_blocked": {
        "control": "DLP",
        "title": "Recipe disclosure blocked",
        "explanation": "Recipe clues (ingredients, quantities, steps, times) accumulated across your "
                       "recent messages in this room reached the review range and the local "
                       "classifier judged the conversation to disclose the secret recipe.",
    },
    "security_check_unavailable": {
        "control": "DLP",
        "title": "Review required but unavailable",
        "explanation": "The message needed local-model review (recipe score 30-99) and the local "
                       "model was missing, timed out or returned an invalid answer. Unreviewed "
                       "content is never delivered (fail closed).",
    },
    "malicious_url": {
        "control": "Anti-Bot",
        "title": "Malicious link blocked",
        "explanation": "A link in the message points to a host that at least two VirusTotal "
                       "engines flag as malicious. The link was never visited; only the hostname "
                       "reputation was checked.",
    },
    "reputation_review_required": {
        "control": "Anti-Bot",
        "title": "Uncertain link reputation",
        "explanation": "A link's host has an uncertain reputation: a single malicious detection, a "
                       "suspicious flag, no or stale report, or an IP/internal host that cannot be "
                       "checked. Uncertain links are not delivered.",
    },
    "reputation_unavailable": {
        "control": "Anti-Bot",
        "title": "Reputation service unavailable",
        "explanation": "The link's reputation could not be checked: missing VirusTotal API key, "
                       "provider error, timeout, or rate limit. Unverified links are not delivered "
                       "(fail closed); the next attempt retries.",
    },
}

REQUEST_ERRORS: dict[str, str] = {
    "invalid_request": "The request is malformed or a required field is missing or empty.",
    "invalid_json": "The frame is not valid JSON.",
    "unsupported_operation": "Unknown action.",
    "unauthenticated": "Log in first; only authenticated users may use rooms or chat.",
    "invalid_username": "Usernames are 3-20 lowercase letters, digits or underscores.",
    "invalid_password": "Passwords are 8-32 characters from letters, digits and @#$%^&*, "
                        "with at least two of those categories.",
    "username_taken": "That username already exists.",
    "invalid_credentials": "Unknown username or wrong password.",
    "invalid_room_name": "Room names must be non-empty without leading or trailing spaces.",
    "group_not_found": "No room with that name exists.",
    "group_already_exists": "A room with that name already exists.",
    "already_member": "You are already an active member of that room.",
    "not_active_member": "You are not an active member of that room; join it first.",
    "room_not_selected": "Select (open) the room on this connection before sending to it.",
    "internal_error": "Unexpected server error; see the server log.",
}


def describe(code: str) -> str:
    """Short one-line explanation for a code, or an empty string when unknown."""
    if code in SECURITY_REASONS:
        entry = SECURITY_REASONS[code]
        return f"{entry['control']}: {entry['title']}."
    return REQUEST_ERRORS.get(code, "")
