# File: azureadgraph_consts.py
#
# Copyright (c) 2019-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
TC_STATUS_SLEEP = 2
PHANTOM_SYS_INFO_URL = "{base_url}rest/system_info"
PHANTOM_ASSET_INFO_URL = "{base_url}rest/asset/{asset_id}"

AZUREADGRAPH_API_URL = "https://graph.windows.net"

MS_AZURE_CONFIG_TENANT = 'tenant_id'
MS_AZURE_CONFIG_SUBSCRIPTION = 'subscription_id'
MS_AZURE_CONFIG_CLIENT_ID = 'client_id'
MS_AZURE_CONFIG_CLIENT_SECRET = 'client_secret'
MS_AZURE_CONFIG_ADMIN_ACCESS = 'admin_access'
MS_AZURE_TOKEN_STRING = 'token'
MS_AZURE_ACCESS_TOKEN_STRING = 'access_token'
MS_AZURE_REFRESH_TOKEN_STRING = 'refresh_token'
MS_AZURE_PHANTOM_BASE_URL = '{phantom_base_url}rest'
MS_AZURE_PHANTOM_SYS_INFO_URL = '/system_info'
MS_AZURE_PHANTOM_ASSET_INFO_URL = '/asset/{asset_id}'
MS_AZURE_BASE_URL_NOT_FOUND_MSG = 'Phantom Base URL not found in System Settings. ' \
                                'Please specify this value in System Settings.'
MS_AZURE_HTML_ERROR = 'Bad Request Bad Request - Invalid URL HTTP Error 400. The request URL is invalid.'
MS_AZURE_NEXT_LINK_STRING = 'odata.nextLink'
MS_AZURE_PAGE_SIZE = 999

# For authorization code
TC_FILE = "oauth_task.out"
SERVER_TOKEN_URL = "https://login.microsoftonline.com/{0}/oauth2/token"

MS_REST_URL_NOT_AVAILABLE_MSG = 'Rest URL not available. Error: {error}'
MS_OAUTH_URL_MSG = 'Using OAuth URL:\n'
MS_AUTHORIZE_USER_MSG = 'Please authorize user in a separate tab using URL:'
MS_GENERATING_ACCESS_TOKEN_MSG = 'Generating access token'
MS_TC_STATUS_SLEEP = 3
MS_AZURE_CODE_GENERATION_SCOPE = 'Group.ReadWrite.All User.Read.All User.ReadWrite.All Directory.ReadWrite.All'
MS_AZURE_AUTHORIZE_TROUBLESHOOT_MSG = 'If authorization URL fails to communicate with your Phantom instance, check whether you have:  '\
                                ' 1. Specified the Web Redirect URL of your App -- The Redirect URL should be <POST URL>/result . '\
                                ' 2. Configured the base URL of your Phantom Instance at Administration -> Company Settings -> Info'
