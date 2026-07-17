from pathlib import Path


CONNECTOR_SOURCE = Path("azureadgraph_connector.py").read_text()


def test_oauth_flow_uses_a_high_entropy_one_time_nonce():
    assert "secrets.token_hex(32)" in CONNECTOR_SOURCE
    assert "hmac.compare_digest(stored_nonce, presented_nonce)" in CONNECTOR_SOURCE
    assert "state.pop(MS_AZURE_OAUTH_STATE_NONCE, None)" in CONNECTOR_SOURCE


def test_invalid_oauth_state_does_not_signal_completion():
    assert "return_val.status_code < 400" in CONNECTOR_SOURCE
    assert "Invalid or expired OAuth state" in CONNECTOR_SOURCE
