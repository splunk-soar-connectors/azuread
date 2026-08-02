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
import ast
import unittest
from pathlib import Path


CONNECTOR = Path(__file__).resolve().parents[1] / "azureadgraph_connector.py"


def _function_source(name):
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)
    return ast.get_source_segment(source, function)


class ValidationFollowupTests(unittest.TestCase):
    def test_oauth_start_requires_the_pending_nonce(self):
        source = _function_source("_handle_login_redirect")
        self.assertIn('request.GET.get("state_nonce", "")', source)
        self.assertIn("hmac.compare_digest", source)
        self.assertLess(source.index("hmac.compare_digest"), source.index("state.get(key)"))

    def test_displayed_oauth_start_link_carries_the_nonce(self):
        source = _function_source("_handle_test_connectivity")
        self.assertIn('"state_nonce": oauth_state_nonce', source)
        self.assertIn("urlparse.urlencode", source)

    def test_rest_responses_are_streamed_before_parsing(self):
        source = _function_source("_make_rest_call")
        self.assertIn("stream=True", source)
        self.assertIn("r.iter_content", source)
        self.assertIn("MAX_RESPONSE_BYTES", source)
        self.assertLess(source.index("r.iter_content"), source.index("_process_response"))


if __name__ == "__main__":
    unittest.main()
