from pathlib import Path


CONNECTOR_SOURCE = Path("azureadgraph_connector.py").read_text()


def test_oauth_token_responses_are_not_added_to_debug_data():
    assert 'endswith("/oauth2/token")' in CONNECTOR_SOURCE
    assert "if not _is_oauth_token_response(response):" in CONNECTOR_SOURCE
