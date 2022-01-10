[comment]: # "Auto-generated SOAR connector documentation"
# Azure AD Graph

Publisher: Splunk
Connector Version: 2\.1\.6
Product Vendor: Microsoft
Product Name: Azure AD Graph
Product Version Supported (regex): "\.\*"
Minimum Product Version: 4\.10\.0\.40961

Connects to Azure AD Graph REST API services

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2019-2021 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Authentication

This app requires creating a Microsoft Azure Application. To do so, navigate to
<https://portal.azure.com> in a browser and log in with a Microsoft account, then select **Azure
Active Directory** .

1.  Go to **App Registrations** and click on **+ New registration** .
2.  Give the app an appropriate name. The Redirect URI will be populated in a later step.
3.  Select a supported account type (configure the application to be multitenant).
4.  Click on the **Register** .
    -   Under **Certificates & secrets** , add **New client secret** . Note this key somewhere
        secure, as it cannot be retrieved after closing the window.
    -   Under **Redirect URIs** we will be updating the entry of https://phantom.local to reflect
        the actual redirect URI. We will get this from the Phantom asset we create below in the
        section titled "Configure the Azure AD Graph Phantom app Asset"
    -   Under **API Permissions** , click on **Add a permission** .
    -   Go to **Microsoft Graph Permissions** , the following **Delegated Permissions** need to be
        added:
        -   User.Read
        -   User.Read.All
        -   Directory.ReadWrite.All
        -   Directory.AccessAsUser.All
        -   Directory.ReadWrite.All
    -   Click on the **Add permissions** .

After making these changes, click on **Grant admin consent** .

## Configure the Azure AD Graph Phantom app Asset

When creating an asset for the **Azure AD Graph** app, place the **Application ID** of the app
created during the previous step in the **Client ID** field and place the password generated during
the app creation process in the **Client Secret** field. Then, after filling out the **Tenant**
field, click **SAVE** .

After saving, a new field will appear in the **Asset Settings** tab. Take the URL found in the
**POST incoming for Azure AD Graph to this location** field and place it in the **Redirect URIs**
field mentioned in a previous step. To this URL, add **/result** . After doing so the URL should
look something like:


https://\<phantom_host>/rest/handler/azureadgraph_c6d3b801-5c26-4abd-9e89-6d8007e2778f/\<asset_name>/result


Once again, click on Save.

## User Permissions

To complete the authorization process, this app needs permission to view assets, which is not
granted by default. First, under **asset settings** , check which user is listed under **Select a
user on behalf of which automated actions can be executed** . By default, the user will be
**automation** , but this user can be changed by clicking **EDIT** at the bottom of the window. To
give this user permission to view assets, follow these steps:

-   In the main drop-down menu, select **Administration** , then select the **User Management** ,
    and under that tab, select **Roles** . Finally, click **+ ROLE** .
-   In the **Add Role** wizard, give the role a name (e.g **Asset Viewer** ), and provide a
    description. Subsequently, under **Available Users** , add the user assigned to the asset viewed
    earlier. Then click the **Permissions** tab.
-   On the permission tab, under **Available Privileges** , give the role the **View Assets**
    privilege. Then click **SAVE** .

## Method to Run Test Connectivity

After setting up the asset and user, click the **TEST CONNECTIVITY** button. A window should pop up
and display a URL. Navigate to this URL in a separate browser tab. This new tab will redirect to a
Microsoft login page. Log in to a Microsoft account with administrator privileges to the Azure AD
environment. After logging in, review the requested permissions listed, then click **Accept** .
Finally, close that tab. The test connectivity window should show a success.

The app should now be ready to use.

## State File Permissions

Please check the permissions for the state file as mentioned below.

#### State Filepath

-   For Non-NRI Instance:
    /opt/phantom/local_data/app_states/c6d3b801-5c26-4abd-9e89-6d8007e2778f/{asset_id}\_state.json
-   For NRI Instance:
    /\<PHANTOM_HOME_DIRECTORY>/local_data/app_states/c6d3b801-5c26-4abd-9e89-6d8007e2778f/{asset_id}\_state.json

#### State File Permissions

-   File Rights: rw-rw-r-- (664) (The phantom user should have read and write access for the state
    file)
-   File Owner: appropriate phantom user


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Azure AD Graph asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant\_id** |  required  | string | Tenant \(Tenant ID or Tenant Name\)
**client\_id** |  required  | string | Application ID
**client\_secret** |  required  | password | Client Secret

### Supported Actions
[test connectivity](#action-test-connectivity) - Use supplied credentials to generate a token with MS Graph
[list users](#action-list-users) - List users in a tenant
[reset password](#action-reset-password) - Reset or set a user's password in an Azure AD environment
[disable tokens](#action-disable-tokens) - Invalidate all active refresh tokens for a user in an Azure AD environment
[enable user](#action-enable-user) - Enable a user
[disable user](#action-disable-user) - Disable a user
[list user attributes](#action-list-user-attributes) - List attributes for all or a specified user
[set user attribute](#action-set-user-attribute) - Set an attribute for a user
[remove user](#action-remove-user) - Remove a user from a specified group
[add user](#action-add-user) - Add a user to the tenant by creating an organizational account
[list groups](#action-list-groups) - List groups in the organization
[get group](#action-get-group) - Get information about a group
[list group members](#action-list-group-members) - List the members in a group
[validate group](#action-validate-group) - Returns true if a user is in a group; otherwise, false
[list directory roles](#action-list-directory-roles) - List the directory roles in a tenant
[generate token](#action-generate-token) - Generate a token or regenerates token when the token expires

## action: 'test connectivity'
Use supplied credentials to generate a token with MS Graph

Type: **test**
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output

## action: 'list users'
List users in a tenant

Type: **investigate**
Read only: **True**

For more information on using the filter\_string parameter, refer to https\://docs\.microsoft\.com/en\-us/previous\-versions/azure/ad/graph/howto/azure\-ad\-graph\-api\-supported\-queries\-filters\-and\-paging\-options\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter\_string** |  optional  | Filter string to apply to user listing | string |

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.parameter\.filter\_string | string |
action\_result\.data\.\*\.accountEnabled | boolean |
action\_result\.data\.\*\.ageGroup | string |
action\_result\.data\.\*\.assignedLicenses\.\*\.skuId | string |
action\_result\.data\.\*\.assignedPlans\.\*\.assignedTimestamp | string |
action\_result\.data\.\*\.assignedPlans\.\*\.capabilityStatus | string |
action\_result\.data\.\*\.assignedPlans\.\*\.service | string |
action\_result\.data\.\*\.assignedPlans\.\*\.servicePlanId | string |
action\_result\.data\.\*\.city | string |
action\_result\.data\.\*\.companyName | string |
action\_result\.data\.\*\.consentProvidedForMinor | string |
action\_result\.data\.\*\.country | string |
action\_result\.data\.\*\.createdDateTime | string |
action\_result\.data\.\*\.creationType | string |
action\_result\.data\.\*\.deletionTimestamp | string |
action\_result\.data\.\*\.department | string |
action\_result\.data\.\*\.dirSyncEnabled | string |
action\_result\.data\.\*\.displayName | string |
action\_result\.data\.\*\.employeeId | string |
action\_result\.data\.\*\.facsimileTelephoneNumber | string |
action\_result\.data\.\*\.givenName | string |
action\_result\.data\.\*\.immutableId | string |
action\_result\.data\.\*\.isCompromised | string |
action\_result\.data\.\*\.jobTitle | string |
action\_result\.data\.\*\.lastDirSyncTime | string |
action\_result\.data\.\*\.legalAgeGroupClassification | string |
action\_result\.data\.\*\.mail | string |  `email`
action\_result\.data\.\*\.mailNickname | string |
action\_result\.data\.\*\.mobile | string |
action\_result\.data\.\*\.objectId | string |  `azure object id`
action\_result\.data\.\*\.objectType | string |
action\_result\.data\.\*\.odata\.type | string |
action\_result\.data\.\*\.onPremisesDistinguishedName | string |
action\_result\.data\.\*\.onPremisesSecurityIdentifier | string |
action\_result\.data\.\*\.otherMails | string |  `email`
action\_result\.data\.\*\.passwordPolicies | string |
action\_result\.data\.\*\.passwordProfile | string |
action\_result\.data\.\*\.passwordProfile\.enforceChangePasswordPolicy | boolean |
action\_result\.data\.\*\.passwordProfile\.forceChangePasswordNextLogin | boolean |
action\_result\.data\.\*\.passwordProfile\.password | string |
action\_result\.data\.\*\.physicalDeliveryOfficeName | string |
action\_result\.data\.\*\.postalCode | string |
action\_result\.data\.\*\.preferredLanguage | string |
action\_result\.data\.\*\.provisionedPlans\.\*\.capabilityStatus | string |
action\_result\.data\.\*\.provisionedPlans\.\*\.provisioningStatus | string |
action\_result\.data\.\*\.provisionedPlans\.\*\.service | string |
action\_result\.data\.\*\.proxyAddresses | string |
action\_result\.data\.\*\.refreshTokensValidFromDateTime | string |
action\_result\.data\.\*\.showInAddressList | string |
action\_result\.data\.\*\.sipProxyAddress | string |  `email`
action\_result\.data\.\*\.state | string |
action\_result\.data\.\*\.streetAddress | string |
action\_result\.data\.\*\.surname | string |
action\_result\.data\.\*\.telephoneNumber | string |
action\_result\.data\.\*\.thumbnailPhoto\@odata\.mediaEditLink | string |
action\_result\.data\.\*\.usageLocation | string |
action\_result\.data\.\*\.userPrincipalName | string |  `email`  `azure user principal name`
action\_result\.data\.\*\.userState | string |
action\_result\.data\.\*\.userStateChangedOn | string |
action\_result\.data\.\*\.userType | string |
action\_result\.summary\.num\_users | numeric |
action\_result\.summary\.result\_found | boolean |
action\_result\.summary\.total\_results | numeric |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'reset password'
Reset or set a user's password in an Azure AD environment

Type: **contain**
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | User ID to change password \- can be user principal name or object ID | string |  `azure user principal name`  `azure object id`  `email`
**force\_change** |  optional  | Force user to change password on next login | boolean |
**temp\_password** |  required  | Temporary password for user | string |

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.parameter\.force\_change | boolean |
action\_result\.parameter\.temp\_password | string |
action\_result\.parameter\.user\_id | string |  `azure user principal name`  `azure object id`  `email`
action\_result\.data | string |
action\_result\.summary\.status | string |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'disable tokens'
Invalidate all active refresh tokens for a user in an Azure AD environment

Type: **contain**
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | User ID to disable tokens of \- can be user principal name or object ID | string |  `azure user principal name`  `azure object id`  `email`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.parameter\.user\_id | string |  `azure user principal name`  `azure object id`  `email`
action\_result\.data | string |
action\_result\.data\.\*\.odata\.metadata | string |  `url`
action\_result\.data\.\*\.odata\.null | boolean |
action\_result\.summary\.status | string |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'enable user'
Enable a user

Type: **generic**
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | User ID to enable tokens of \- can be user principal name or object ID | string |  `azure user principal name`  `azure object id`  `email`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.parameter\.user\_id | string |  `azure user principal name`  `azure object id`  `email`
action\_result\.data | string |
action\_result\.summary\.status | string |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'disable user'
Disable a user

Type: **generic**
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | User ID to change password \- can be user principal name or object ID | string |  `azure user principal name`  `azure object id`  `email`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.parameter\.user\_id | string |  `azure user principal name`  `azure object id`  `email`
action\_result\.data | string |
action\_result\.summary\.status | string |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'list user attributes'
List attributes for all or a specified user

Type: **investigate**
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  optional  | User ID \- can be user principal name or object ID | string |  `azure user principal name`  `azure object id`  `email`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.parameter\.user\_id | string |  `azure user principal name`  `azure object id`  `email`
action\_result\.data\.\*\.accountEnabled | boolean |
action\_result\.data\.\*\.ageGroup | string |
action\_result\.data\.\*\.assignedLicenses\.\*\.skuId | string |
action\_result\.data\.\*\.assignedPlans\.\*\.assignedTimestamp | string |
action\_result\.data\.\*\.assignedPlans\.\*\.capabilityStatus | string |
action\_result\.data\.\*\.assignedPlans\.\*\.service | string |
action\_result\.data\.\*\.assignedPlans\.\*\.servicePlanId | string |
action\_result\.data\.\*\.city | string |
action\_result\.data\.\*\.companyName | string |
action\_result\.data\.\*\.consentProvidedForMinor | string |
action\_result\.data\.\*\.country | string |
action\_result\.data\.\*\.createdDateTime | string |
action\_result\.data\.\*\.creationType | string |
action\_result\.data\.\*\.deletionTimestamp | string |
action\_result\.data\.\*\.department | string |
action\_result\.data\.\*\.dirSyncEnabled | string |
action\_result\.data\.\*\.displayName | string |
action\_result\.data\.\*\.employeeId | string |
action\_result\.data\.\*\.facsimileTelephoneNumber | string |
action\_result\.data\.\*\.givenName | string |
action\_result\.data\.\*\.immutableId | string |
action\_result\.data\.\*\.isCompromised | string |
action\_result\.data\.\*\.jobTitle | string |
action\_result\.data\.\*\.lastDirSyncTime | string |
action\_result\.data\.\*\.legalAgeGroupClassification | string |
action\_result\.data\.\*\.mail | string |  `email`
action\_result\.data\.\*\.mailNickname | string |
action\_result\.data\.\*\.mobile | string |
action\_result\.data\.\*\.objectId | string |
action\_result\.data\.\*\.objectType | string |
action\_result\.data\.\*\.odata\.metadata | string |
action\_result\.data\.\*\.odata\.type | string |
action\_result\.data\.\*\.onPremisesDistinguishedName | string |
action\_result\.data\.\*\.onPremisesSecurityIdentifier | string |
action\_result\.data\.\*\.otherMails | string |  `email`
action\_result\.data\.\*\.passwordPolicies | string |
action\_result\.data\.\*\.passwordProfile | string |
action\_result\.data\.\*\.passwordProfile\.enforceChangePasswordPolicy | boolean |
action\_result\.data\.\*\.passwordProfile\.forceChangePasswordNextLogin | boolean |
action\_result\.data\.\*\.passwordProfile\.password | string |
action\_result\.data\.\*\.physicalDeliveryOfficeName | string |
action\_result\.data\.\*\.postalCode | string |
action\_result\.data\.\*\.preferredLanguage | string |
action\_result\.data\.\*\.provisionedPlans\.\*\.capabilityStatus | string |
action\_result\.data\.\*\.provisionedPlans\.\*\.provisioningStatus | string |
action\_result\.data\.\*\.provisionedPlans\.\*\.service | string |
action\_result\.data\.\*\.proxyAddresses | string |
action\_result\.data\.\*\.refreshTokensValidFromDateTime | string |
action\_result\.data\.\*\.showInAddressList | string |
action\_result\.data\.\*\.sipProxyAddress | string |  `email`
action\_result\.data\.\*\.state | string |
action\_result\.data\.\*\.streetAddress | string |
action\_result\.data\.\*\.surname | string |
action\_result\.data\.\*\.telephoneNumber | string |
action\_result\.data\.\*\.thumbnailPhoto\@odata\.mediaEditLink | string |
action\_result\.data\.\*\.usageLocation | string |
action\_result\.data\.\*\.userPrincipalName | string |  `email`
action\_result\.data\.\*\.userState | string |
action\_result\.data\.\*\.userStateChangedOn | string |
action\_result\.data\.\*\.userType | string |
action\_result\.summary\.status | string |
action\_result\.summary\.user\_enabled | boolean |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'set user attribute'
Set an attribute for a user

Type: **generic**
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | User ID \- can be user principal name or object ID | string |  `azure user principal name`  `azure object id`  `email`
**attribute** |  required  | Attribute to set | string |
**attribute\_value** |  required  | Value of attribute to set | string |

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.parameter\.attribute | string |
action\_result\.parameter\.attribute\_value | string |
action\_result\.parameter\.user\_id | string |  `azure user principal name`  `azure object id`  `email`
action\_result\.data | string |
action\_result\.summary\.status | string |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'remove user'
Remove a user from a specified group

Type: **generic**
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_object\_id** |  required  | Object ID of group | string |  `azure group object id`
**user\_id** |  required  | User ID to remove from group | string |  `azure user principal name`  `azure object id`  `email`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.parameter\.group\_object\_id | string |  `azure group object id`
action\_result\.parameter\.user\_id | string |  `azure user principal name`  `azure object id`  `email`
action\_result\.data | string |
action\_result\.summary\.status | string |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'add user'
Add a user to the tenant by creating an organizational account

Type: **generic**
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_object\_id** |  required  | Object ID of group | string |  `azure group object id`
**user\_id** |  required  | User ID to add to group | string |  `azure object id`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.parameter\.group\_object\_id | string |  `azure group object id`
action\_result\.parameter\.user\_id | string |  `azure object id`
action\_result\.data | string |
action\_result\.summary\.status | string |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'list groups'
List groups in the organization

Type: **investigate**
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.data\.\*\.deletionTimestamp | string |
action\_result\.data\.\*\.description | string |
action\_result\.data\.\*\.dirSyncEnabled | string |
action\_result\.data\.\*\.displayName | string |
action\_result\.data\.\*\.lastDirSyncTime | string |
action\_result\.data\.\*\.mail | string |  `email`
action\_result\.data\.\*\.mailEnabled | boolean |
action\_result\.data\.\*\.mailNickname | string |
action\_result\.data\.\*\.objectId | string |  `azure object id`
action\_result\.data\.\*\.objectType | string |
action\_result\.data\.\*\.odata\.type | string |
action\_result\.data\.\*\.onPremisesDomainName | string |  `domain`
action\_result\.data\.\*\.onPremisesNetBiosName | string |
action\_result\.data\.\*\.onPremisesSamAccountName | string |
action\_result\.data\.\*\.onPremisesSecurityIdentifier | string |
action\_result\.data\.\*\.proxyAddresses | string |
action\_result\.data\.\*\.securityEnabled | boolean |
action\_result\.summary\.num\_groups | numeric |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'get group'
Get information about a group

Type: **investigate**
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**object\_id** |  required  | Object ID of group | string |  `azure object id`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.parameter\.object\_id | string |  `azure object id`
action\_result\.data\.\*\.deletionTimestamp | string |
action\_result\.data\.\*\.description | string |
action\_result\.data\.\*\.dirSyncEnabled | string |
action\_result\.data\.\*\.displayName | string |
action\_result\.data\.\*\.lastDirSyncTime | string |
action\_result\.data\.\*\.mail | string |  `email`
action\_result\.data\.\*\.mailEnabled | boolean |
action\_result\.data\.\*\.mailNickname | string |
action\_result\.data\.\*\.objectId | string |  `azure object id`
action\_result\.data\.\*\.objectType | string |
action\_result\.data\.\*\.odata\.metadata | string |
action\_result\.data\.\*\.odata\.type | string |
action\_result\.data\.\*\.onPremisesDomainName | string |  `domain`
action\_result\.data\.\*\.onPremisesNetBiosName | string |
action\_result\.data\.\*\.onPremisesSamAccountName | string |
action\_result\.data\.\*\.onPremisesSecurityIdentifier | string |
action\_result\.data\.\*\.proxyAddresses | string |
action\_result\.data\.\*\.securityEnabled | boolean |
action\_result\.summary\.display\_name | string |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'list group members'
List the members in a group

Type: **investigate**
Read only: **True**

<p>Pagination is not implemented for this action as this endpoint does not support pagination\. Here is the <b><a href='https\://docs\.microsoft\.com/en\-us/previous\-versions/azure/ad/graph/howto/azure\-ad\-graph\-api\-supported\-queries\-filters\-and\-paging\-options' target='\_blank'>Documentation</a></b> for the same\.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_object\_id** |  required  | Object ID of group | string |  `azure object id`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.parameter\.group\_object\_id | string |  `azure object id`
action\_result\.data\.\*\.displayName | string |
action\_result\.data\.\*\.objectId | string |  `azure object id`
action\_result\.summary\.num\_members | numeric |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'validate group'
Returns true if a user is in a group; otherwise, false

Type: **investigate**
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_object\_id** |  required  | Object ID of group | string |  `azure group object id`
**user\_id** |  required  | User ID to validate | string |  `azure user principal name`  `azure object id`  `email`

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.parameter\.group\_object\_id | string |  `azure group object id`
action\_result\.parameter\.user\_id | string |  `azure user principal name`  `azure object id`  `email`
action\_result\.data\.\*\.user\_in\_group | boolean |
action\_result\.summary\.user\_in\_group | boolean |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'list directory roles'
List the directory roles in a tenant

Type: **investigate**
Read only: **True**

<p>Pagination is not implemented for this action as this endpoint does not support pagination\. Here is the <b><a href='https\://docs\.microsoft\.com/en\-us/previous\-versions/azure/ad/graph/howto/azure\-ad\-graph\-api\-supported\-queries\-filters\-and\-paging\-options' target='\_blank'>Documentation</a></b> for the same\.</p>

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.data\.\*\.deletionTimestamp | string |
action\_result\.data\.\*\.description | string |
action\_result\.data\.\*\.displayName | string |
action\_result\.data\.\*\.isSystem | boolean |
action\_result\.data\.\*\.objectId | string |  `azure object id`
action\_result\.data\.\*\.objectType | string |
action\_result\.data\.\*\.odata\.type | string |
action\_result\.data\.\*\.roleDisabled | boolean |
action\_result\.data\.\*\.roleTemplateId | string |  `azure role template id`
action\_result\.summary\.num\_directory\_roles | numeric |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |

## action: 'generate token'
Generate a token or regenerates token when the token expires

Type: **generic**
Read only: **False**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string |
action\_result\.data | string |
action\_result\.summary | string |
action\_result\.message | string |
summary\.total\_objects | numeric |
summary\.total\_objects\_successful | numeric |
