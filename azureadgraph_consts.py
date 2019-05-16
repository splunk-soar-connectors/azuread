# File: azureadgraph_consts.py
# Copyright (c) 2018-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


MS_AZURE_CONFIG_TENANT = 'tenant_id'
MS_AZURE_CONFIG_CLIENT_ID = 'client_id'
MS_AZURE_TOKEN_STRING = 'token'
MS_AZURE_ACCESS_TOKEN_STRING = 'access_token'
MS_AZURE_REFRESH_TOKEN_STRING = 'refresh_token'

TC_STATUS_SLEEP = 2
PHANTOM_SYS_INFO_URL = "{base_url}rest/system_info"
PHANTOM_ASSET_INFO_URL = "{base_url}rest/asset/{asset_id}"
O365_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

AZUREADGRAPH_API_URL = "https://graph.windows.net"

VM_GET_SYSTEM_INFO_ENDPOINT = "/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}?api-version=2018-06-01"
VM_LIST_VMS_RESOURCE_GROUP_ENDPOINT = "/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines?api-version=2018-06-01"
VM_LIST_VMS_ALL_ENDPOINT = "/providers/Microsoft.Compute/virtualMachines?api-version=2018-06-01"
VM_ACTION_ENDPOINT = "/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/{action}?api-version=2018-06-01"
VM_SNAPSHOT_VM_ENDPOINT = "/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/snapshots/{snapshotName}?api-version=2018-06-01"
VM_LIST_TAGS_ENDPOINT = "/tagNames?api-version=2018-05-01"
VM_CREATE_TAG_ENDPOINT = "/tagNames/{tagName}{tagValue}?api-version=2018-05-01"
VM_CREATE_TAG_VALUE_PART = "/tagValues/{tagValue}"
VM_RESOURCE_GROUP_ENDPOINT = "/resourcegroups?api-version=2018-05-01"
VM_LIST_SNAPSHOTS_ENDPOINT = "{resourceValue}/providers/Microsoft.Compute/snapshots?api-version=2018-06-01"
VM_RESOURCE_GROUP_VALUE_PART = "/resourceGroups/{resourceGroupName}"
VM_SECURITY_GROUP_ENDPOINT = "/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/{groupType}{groupName}?api-version=2018-11-01"
VM_LIST_VIRTUAL_NETWORKS_ENDPOINT = "{resourceGroup}/providers/Microsoft.Network/virtualNetworks?api-version=2018-11-01"
VM_LIST_SUBNETS_ENDPOINT = "/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks/{virtualNetworkName}/subnets?api-version=2018-11-01"
VM_CHECK_IP_AVAIL = "/resourceGroups/{resourceGroup}/providers/Microsoft.Network/virtualNetworks/{virtualNetwork}/CheckIPAddressAvailability?ipAddress={ip}&api-version=2018-11-01"
VM_RUN_COMMAND_ENDPOINT = "/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/runCommand?api-version=2017-03-30"

TEST_CONNECTIVITY_FAILED_MSG = 'Test Connectivity Failed'
MS_PHANTOM_SYS_INFO_URL = "{url}rest/system_info"
MS_PHANTOM_ASSET_INFO_URL = "{url}rest/asset/{asset_id}"

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
MS_AZURE_CODE_GENERATION_SCOPE = '"Calendars.ReadWrite Group.ReadWrite.All Mail.Read Mail.ReadWrite User.Read.All User.ReadWrite.All"'
