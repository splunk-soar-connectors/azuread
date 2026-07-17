import json
from pathlib import Path


CONNECTOR_SOURCE = Path("azureadgraph_connector.py").read_text()
APP_JSON = json.loads(Path("azureadgraph.json").read_text())


def test_disable_user_invalidates_refresh_tokens():
    disable_user_source = CONNECTOR_SOURCE.split("def _handle_disable_user", 1)[1].split("def _handle_list_user_attributes", 1)[0]
    assert "invalidateAllRefreshTokens" in disable_user_source
    assert 'method="post"' in disable_user_source


def test_disable_user_documents_remaining_access_token_window():
    disable_user = next(action for action in APP_JSON["actions"] if action["identifier"] == "disable_user")
    assert "Existing access tokens remain valid until they expire" in disable_user["description"]
