# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
from pathlib import Path


CONNECTOR_SOURCE = Path("azureadgraph_connector.py").read_text()
APP_JSON = json.loads(Path("azureadgraph.json").read_text())


def test_temporary_password_is_masked_and_not_rendered():
    reset_password = next(action for action in APP_JSON["actions"] if action["identifier"] == "reset_password")
    assert reset_password["parameters"]["temp_password"]["data_type"] == "password"
    password_output = next(output for output in reset_password["output"] if output.get("data_path") == "action_result.parameter.temp_password")
    assert password_output["data_type"] == "password"


def test_temporary_password_is_not_copied_to_action_result_parameters():
    assert 'safe_param.pop("temp_password", None)' in CONNECTOR_SOURCE
    assert "ActionResult(safe_param)" in CONNECTOR_SOURCE
