from pathlib import Path


CONNECTOR_SOURCE = Path("azureadgraph_connector.py").read_text()


def test_ambiguous_remove_user_failure_verifies_that_group_exists():
    assert 'group_endpoint = f"/groups/{_quote_path_segment(object_id)}"' in CONNECTOR_SOURCE
    assert "Unable to verify group" in CONNECTOR_SOURCE
    assert CONNECTOR_SOURCE.index("Unable to verify group") < CONNECTOR_SOURCE.index('summary["status"] = "User not in group"')
