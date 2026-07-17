from pathlib import Path


CONNECTOR_SOURCE = Path("azureadgraph_connector.py").read_text()
CONSTS_SOURCE = Path("azureadgraph_consts.py").read_text()


def test_pagination_has_page_and_item_limits():
    assert "MS_AZURE_MAX_PAGINATION_PAGES = 1000" in CONSTS_SOURCE
    assert "MS_AZURE_MAX_PAGINATION_ITEMS = 100000" in CONSTS_SOURCE
    assert "page_count >= MS_AZURE_MAX_PAGINATION_PAGES" in CONNECTOR_SOURCE
    assert "item_count + len(page_items) > MS_AZURE_MAX_PAGINATION_ITEMS" in CONNECTOR_SOURCE


def test_pagination_rejects_missing_or_repeated_skip_tokens():
    assert "Unable to extract skiptoken from odata.nextLink" in CONNECTOR_SOURCE
    assert "skip_token in seen_skip_tokens" in CONNECTOR_SOURCE
