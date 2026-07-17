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
from pathlib import Path


WIDGET_SOURCE = Path("azureadgraph_list_user_attributes.html").read_text()


def test_context_menu_values_are_javascript_escaped():
    assert "curr_data.userPrincipalName|escapejs" in WIDGET_SOURCE
    assert "curr_data.objectId|escapejs" in WIDGET_SOURCE
