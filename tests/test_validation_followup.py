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
        self.assertLess(source.index("hmac.compare_digest"), source.index('state.get(key)'))

    def test_displayed_oauth_start_link_carries_the_nonce(self):
        source = _function_source("_handle_test_connectivity")
        self.assertIn('"state_nonce": oauth_state_nonce', source)
        self.assertIn("urlparse.urlencode", source)

if __name__ == "__main__":
    unittest.main()
