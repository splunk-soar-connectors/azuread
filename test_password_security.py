import json
from pathlib import Path


CONNECTOR_SOURCE = Path("azureadgraph_connector.py").read_text()
APP_JSON = json.loads(Path("azureadgraph.json").read_text())


def test_temporary_password_is_masked_and_not_rendered():
    reset_password = next(action for action in APP_JSON["actions"] if action["identifier"] == "reset_password")
    assert reset_password["parameters"]["temp_password"]["data_type"] == "password"
    assert all(output.get("data_path") != "action_result.parameter.temp_password" for output in reset_password["output"])


def test_temporary_password_is_not_copied_to_action_result_parameters():
    assert 'safe_param.pop("temp_password", None)' in CONNECTOR_SOURCE
    assert "ActionResult(safe_param)" in CONNECTOR_SOURCE
