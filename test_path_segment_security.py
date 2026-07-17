from pathlib import Path


CONNECTOR_SOURCE = Path("azureadgraph_connector.py").read_text()


def test_action_identifiers_are_encoded_as_single_path_segments():
    assert 'urlparse.quote(str(value), safe="").replace(".", "%2E")' in CONNECTOR_SOURCE
    assert CONNECTOR_SOURCE.count("_quote_path_segment(") >= 13


def test_raw_identifiers_are_not_interpolated_into_endpoints():
    assert 'f"/users/{user_id}' not in CONNECTOR_SOURCE
    assert 'f"/groups/{object_id}' not in CONNECTOR_SOURCE
    assert '/members/{user_id}' not in CONNECTOR_SOURCE
