"""Fast, isolated reliability coverage for the live WebSocket protocol."""
from scripts.load_test import run_scenario


def test_concurrent_chat_reliability():
    result = run_scenario(client_count=3, message_count=2)

    assert result["failed"] == 0
    assert result["unexpected_disconnects"] == 0
    assert result["verified_alpha_messages"] == 5
    assert result["verified_beta_isolation"] is True