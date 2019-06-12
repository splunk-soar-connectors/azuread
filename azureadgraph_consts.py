# File: azureadgraph_consts.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


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

# For authorization code
TC_FILE = "oauth_task.out"
SERVER_TOKEN_URL = "https://login.microsoftonline.com/{0}/oauth2/token"

MS_REST_URL_NOT_AVAILABLE_MSG = 'Rest URL not available. Error: {error}'
MS_OAUTH_URL_MSG = 'Using OAuth URL:'
MS_AUTHORIZE_USER_MSG = 'Please authorize user in a separate tab using URL:'
MS_GENERATING_ACCESS_TOKEN_MSG = 'Generating access token'
MS_TC_STATUS_SLEEP = 3
MS_AZURE_CODE_GENERATION_SCOPE = 'Group.ReadWrite.All User.Read.All User.ReadWrite.All Directory.ReadWrite.All'
