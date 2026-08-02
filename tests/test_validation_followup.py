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
        self.assertIn("allow_redirects=False", source)
        self.assertLess(source.index("r.iter_content"), source.index("_process_response"))

    def test_pagination_has_an_action_wide_response_budget(self):
        source = _function_source("_handle_pagination")
        self.assertIn('response_budget = {"bytes": 0}', source)
        self.assertIn("response_budget=response_budget", source)
        self.assertIn("MAX_PAGINATION_ITEM_BYTES", source)
        self.assertIn("MAX_SKIP_TOKEN_BYTES", source)

    def test_every_request_attempt_is_charged_before_response_processing(self):
        rest_call = _function_source("_make_rest_call")
        helper = _function_source("_make_rest_call_helper")
        self.assertIn('response_budget["bytes"] += response_size', rest_call)
        self.assertIn("MAX_PAGINATION_RESPONSE_BYTES", rest_call)
        self.assertLess(rest_call.index('response_budget["bytes"] += response_size'), rest_call.index("_process_response"))
        self.assertEqual(helper.count("response_budget,"), 2)


if __name__ == "__main__":
    unittest.main()
