from pathlib import Path


WIDGET_SOURCE = Path("azureadgraph_list_user_attributes.html").read_text()


def test_context_menu_values_are_javascript_escaped():
    assert "curr_data.userPrincipalName|escapejs" in WIDGET_SOURCE
    assert "curr_data.objectId|escapejs" in WIDGET_SOURCE
