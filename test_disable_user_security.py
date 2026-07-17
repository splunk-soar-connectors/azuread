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


def test_disable_user_invalidates_refresh_tokens():
    disable_user_source = CONNECTOR_SOURCE.split("def _handle_disable_user", 1)[1].split("def _handle_list_user_attributes", 1)[0]
    assert "invalidateAllRefreshTokens" in disable_user_source
    assert 'method="post"' in disable_user_source


def test_disable_user_documents_remaining_access_token_window():
    disable_user = next(action for action in APP_JSON["actions"] if action["identifier"] == "disable_user")
    assert "Existing access tokens remain valid until they expire" in disable_user["description"]
