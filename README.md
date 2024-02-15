[comment]: # "Auto-generated SOAR connector documentation"
# Azure AD Graph

Publisher: Splunk  
Connector Version: 2.5.0  
Product Vendor: Microsoft  
Product Name: Azure AD Graph  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.1.1  

Connects to Azure AD Graph REST API services

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2024 Splunk Inc."
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
    -   Click on the **Add permissions** .

  
  
**Note\*** You must ensure that the Azure Active Directory user account that will be used during the
interactive authentication (described in "Method to Run Test Connectivity below) has a permanently
assigned role that has sufficient permissions as Azure provides the option to revoke roles assigned
to user accounts automatically at a given frequency. After making these changes, click on **Grant
admin consent** .

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

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Azure AD server. Below are the default
ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Azure AD Graph asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant_id** |  required  | string | Tenant (Tenant ID or Tenant Name)
**client_id** |  required  | string | Application ID
**client_secret** |  required  | password | Client Secret
**region** |  optional  | string | Azure AD Region

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

<p>For more information on using the filter_string parameter, refer to <a href='https://docs.microsoft.com/en-us/previous-versions/azure/ad/graph/howto/azure-ad-graph-api-supported-queries-filters-and-paging-options' target='_blank'>https://docs.microsoft.com/en-us/previous-versions/azure/ad/graph/howto/azure-ad-graph-api-supported-queries-filters-and-paging-options</a>.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter_string** |  optional  | Filter string to apply to user listing | string | 
**expand_string** |  optional  | Expand string to get a resource or collection referenced by a single relationship | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.filter_string | string |  |   startswith(displayName,'User') 
action_result.parameter.expand_string | string |  |   manager 
action_result.data.\*.accountEnabled | boolean |  |   True  False 
action_result.data.\*.ageGroup | string |  |  
action_result.data.\*.assignedLicenses.\*.skuId | string |  |   189a915c-fe4f-4ffa-bde4-85b9628d07a0 
action_result.data.\*.assignedPlans.\*.assignedTimestamp | string |  |   2017-08-29T02:31:40Z 
action_result.data.\*.assignedPlans.\*.capabilityStatus | string |  |   Enabled 
action_result.data.\*.assignedPlans.\*.service | string |  |   OfficeForms 
action_result.data.\*.assignedPlans.\*.servicePlanId | string |  |   e212cbc7-0961-4c40-9825-01117710dcb1 
action_result.data.\*.city | string |  |   Palo Alto 
action_result.data.\*.companyName | string |  |  
action_result.data.\*.consentProvidedForMinor | string |  |  
action_result.data.\*.country | string |  |   US 
action_result.data.\*.createdDateTime | string |  |   2019-05-21T22:27:20Z 
action_result.data.\*.creationType | string |  |  
action_result.data.\*.deletionTimestamp | string |  |  
action_result.data.\*.department | string |  |   Sales 
action_result.data.\*.dirSyncEnabled | string |  |  
action_result.data.\*.displayName | string |  |   User 
action_result.data.\*.employeeId | string |  |  
action_result.data.\*.facsimileTelephoneNumber | string |  |  
action_result.data.\*.givenName | string |  |   testuser 
action_result.data.\*.immutableId | string |  |  
action_result.data.\*.isCompromised | string |  |  
action_result.data.\*.jobTitle | string |  |   Sales Manager 
action_result.data.\*.lastDirSyncTime | string |  |  
action_result.data.\*.legalAgeGroupClassification | string |  |  
action_result.data.\*.mail | string |  `email`  |   user@test.onmicrosoft.com 
action_result.data.\*.mailNickname | string |  |   testmail 
action_result.data.\*.mobile | string |  |   +1 5556378688 
action_result.data.\*.objectId | string |  `azure object id`  |   e4c722ac-3b83-478d-8f52-c388885dc30f 
action_result.data.\*.objectType | string |  |   User 
action_result.data.\*.odata.type | string |  |   Microsoft.DirectoryServices.User 
action_result.data.\*.onPremisesDistinguishedName | string |  |  
action_result.data.\*.onPremisesSecurityIdentifier | string |  |  
action_result.data.\*.otherMails | string |  `email`  |   user.test@outlook.com 
action_result.data.\*.passwordPolicies | string |  |   None 
action_result.data.\*.passwordProfile | string |  |  
action_result.data.\*.passwordProfile.enforceChangePasswordPolicy | boolean |  |   True  False 
action_result.data.\*.passwordProfile.forceChangePasswordNextLogin | boolean |  |   True  False 
action_result.data.\*.passwordProfile.password | string |  |  
action_result.data.\*.physicalDeliveryOfficeName | string |  |  
action_result.data.\*.postalCode | string |  |   94303 
action_result.data.\*.preferredLanguage | string |  |   en-US 
action_result.data.\*.provisionedPlans.\*.capabilityStatus | string |  |   Enabled 
action_result.data.\*.provisionedPlans.\*.provisioningStatus | string |  |   Success 
action_result.data.\*.provisionedPlans.\*.service | string |  |   exchange 
action_result.data.\*.proxyAddresses | string |  |   SMTP:user1@test.onmicrosoft.com 
action_result.data.\*.refreshTokensValidFromDateTime | string |  |   2017-09-27T22:54:59Z 
action_result.data.\*.showInAddressList | string |  |  
action_result.data.\*.sipProxyAddress | string |  `email`  |   user@test.onmicrosoft.com 
action_result.data.\*.state | string |  |   CA 
action_result.data.\*.streetAddress | string |  |   2479 E. Bayshore Rd. 
action_result.data.\*.surname | string |  |   Test_surname 
action_result.data.\*.telephoneNumber | string |  |  
action_result.data.\*.thumbnailPhoto@odata.mediaEditLink | string |  |   directoryObjects/6132ca31-7a09-434f-a269-abe836d0c01e/Microsoft.DirectoryServices.User/thumbnailPhoto 
action_result.data.\*.usageLocation | string |  |   US 
action_result.data.\*.userPrincipalName | string |  `email`  `azure user principal name`  |   user@test.onmicrosoft.com 
action_result.data.\*.userState | string |  |  
action_result.data.\*.userStateChangedOn | string |  |  
action_result.data.\*.userType | string |  |   Member 
action_result.summary.num_users | numeric |  |   8 
action_result.summary.result_found | boolean |  |   True  False 
action_result.summary.total_results | numeric |  |   7 
action_result.message | string |  |   Successfully listed users 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'reset password'
Reset or set a user's password in an Azure AD environment

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | User ID to change password - can be user principal name or object ID | string |  `azure user principal name`  `azure object id`  `email` 
**force_change** |  optional  | Force user to change password on next login | boolean | 
**temp_password** |  required  | Temporary password for user | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.force_change | boolean |  |   True  False 
action_result.parameter.temp_password | string |  |   Temp_PA$$w0rd 
action_result.parameter.user_id | string |  `azure user principal name`  `azure object id`  `email`  |   ee3dc4f2-70f9-446f-a19e-6b4e95ba030d  user@test.onmicrosoft.com 
action_result.data | string |  |  
action_result.summary.status | string |  |   Successfully reset user password 
action_result.message | string |  |   Status: Successfully reset user password 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'disable tokens'
Invalidate all active refresh tokens for a user in an Azure AD environment

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | User ID to disable tokens of - can be user principal name or object ID | string |  `azure user principal name`  `azure object id`  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.user_id | string |  `azure user principal name`  `azure object id`  `email`  |   ee3dc4f2-70f9-446f-a19e-6b4e95ba030d  user@test.onmicrosoft.com 
action_result.data | string |  |  
action_result.data.\*.odata.metadata | string |  `url`  |   https://graph.windows.net/1t309est-db6c-4tes-t1d2-12bf3456d78d/$metadata#Edm.Null 
action_result.data.\*.odata.null | boolean |  |   True  False 
action_result.data.\*.value | boolean |  |   True  False 
action_result.summary.status | string |  |   Successfully disabled tokens 
action_result.message | string |  |   Status: Successfully disabled tokens 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'enable user'
Enable a user

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | User ID to enable tokens of - can be user principal name or object ID | string |  `azure user principal name`  `azure object id`  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.user_id | string |  `azure user principal name`  `azure object id`  `email`  |   user@test.onmicrosoft.com 
action_result.data | string |  |  
action_result.summary.status | string |  |   Successfully enabled user user@test.onmicrosoft.com 
action_result.message | string |  |   Status: Successfully enabled user user@test.onmicrosoft.com 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'disable user'
Disable a user

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | User ID to change password - can be user principal name or object ID | string |  `azure user principal name`  `azure object id`  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.user_id | string |  `azure user principal name`  `azure object id`  `email`  |   user@test.onmicrosoft.com 
action_result.data | string |  |  
action_result.summary.status | string |  |   Successfully disabled user user@test.onmicrosoft.com 
action_result.message | string |  |   Status: Successfully disabled user user@test.onmicrosoft.com 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list user attributes'
List attributes for all or a specified user

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  optional  | User ID - can be user principal name or object ID | string |  `azure user principal name`  `azure object id`  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.user_id | string |  `azure user principal name`  `azure object id`  `email`  |   user@test.onmicrosoft.com 
action_result.data.\*.accountEnabled | boolean |  |   True  False 
action_result.data.\*.ageGroup | string |  |  
action_result.data.\*.assignedLicenses.\*.skuId | string |  |   f30db892-07e9-47e9-837c-80727f46fd3d 
action_result.data.\*.assignedPlans.\*.assignedTimestamp | string |  |   2019-04-26T07:21:18Z 
action_result.data.\*.assignedPlans.\*.capabilityStatus | string |  |   Enabled 
action_result.data.\*.assignedPlans.\*.service | string |  |   exchange 
action_result.data.\*.assignedPlans.\*.servicePlanId | string |  |   33c4f319-9bdd-48d6-9c4d-410b750a4a5a 
action_result.data.\*.city | string |  |  
action_result.data.\*.companyName | string |  |  
action_result.data.\*.consentProvidedForMinor | string |  |  
action_result.data.\*.country | string |  |  
action_result.data.\*.createdDateTime | string |  |   2019-05-02T20:27:59Z 
action_result.data.\*.creationType | string |  |  
action_result.data.\*.deletionTimestamp | string |  |  
action_result.data.\*.department | string |  |   Sales 
action_result.data.\*.dirSyncEnabled | string |  |  
action_result.data.\*.displayName | string |  |   Luke Skywalker 
action_result.data.\*.employeeId | string |  |  
action_result.data.\*.facsimileTelephoneNumber | string |  |  
action_result.data.\*.givenName | string |  |  
action_result.data.\*.immutableId | string |  |  
action_result.data.\*.isCompromised | string |  |  
action_result.data.\*.jobTitle | string |  |  
action_result.data.\*.lastDirSyncTime | string |  |  
action_result.data.\*.legalAgeGroupClassification | string |  |  
action_result.data.\*.mail | string |  `email`  |  
action_result.data.\*.mailNickname | string |  |   test 
action_result.data.\*.mobile | string |  |  
action_result.data.\*.objectId | string |  |   59f51194-1998-4932-a8ac-468e59374edc 
action_result.data.\*.objectType | string |  |   User 
action_result.data.\*.odata.metadata | string |  |  
action_result.data.\*.odata.type | string |  |   Microsoft.DirectoryServices.User 
action_result.data.\*.onPremisesDistinguishedName | string |  |  
action_result.data.\*.onPremisesSecurityIdentifier | string |  |  
action_result.data.\*.otherMails | string |  `email`  |   user@test.com 
action_result.data.\*.passwordPolicies | string |  |  
action_result.data.\*.passwordProfile | string |  |  
action_result.data.\*.passwordProfile.enforceChangePasswordPolicy | boolean |  |   True  False 
action_result.data.\*.passwordProfile.forceChangePasswordNextLogin | boolean |  |   True  False 
action_result.data.\*.passwordProfile.password | string |  |  
action_result.data.\*.physicalDeliveryOfficeName | string |  |  
action_result.data.\*.postalCode | string |  |  
action_result.data.\*.preferredLanguage | string |  |  
action_result.data.\*.provisionedPlans.\*.capabilityStatus | string |  |   Enabled 
action_result.data.\*.provisionedPlans.\*.provisioningStatus | string |  |   Success 
action_result.data.\*.provisionedPlans.\*.service | string |  |   exchange 
action_result.data.\*.proxyAddresses | string |  |   SMTP:test_shared_mailbox@test.onmicrosoft.com 
action_result.data.\*.refreshTokensValidFromDateTime | string |  |   2019-05-16T19:54:18Z 
action_result.data.\*.showInAddressList | string |  |  
action_result.data.\*.sipProxyAddress | string |  `email`  |  
action_result.data.\*.state | string |  |  
action_result.data.\*.streetAddress | string |  |  
action_result.data.\*.surname | string |  |  
action_result.data.\*.telephoneNumber | string |  |  
action_result.data.\*.thumbnailPhoto@odata.mediaEditLink | string |  |   directoryObjects/59f51194-1998-4932-a8ac-468e59374edc/Microsoft.DirectoryServices.User/thumbnailPhoto 
action_result.data.\*.usageLocation | string |  |   US 
action_result.data.\*.userPrincipalName | string |  `email`  |   user@test.onmicrosoft.com 
action_result.data.\*.userState | string |  |  
action_result.data.\*.userStateChangedOn | string |  |  
action_result.data.\*.userType | string |  |   Member 
action_result.summary.status | string |  |   Successfully retrieved attributes for user user@test.onmicrosoft.com 
action_result.summary.user_enabled | boolean |  |   True  False 
action_result.message | string |  |   Status: Successfully retrieved attributes for user user@test.onmicrosoft.com, User enabled: False 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'set user attribute'
Set an attribute for a user

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | User ID - can be user principal name or object ID | string |  `azure user principal name`  `azure object id`  `email` 
**attribute** |  required  | Attribute to set | string | 
**attribute_value** |  required  | Value of attribute to set | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.attribute | string |  |   department 
action_result.parameter.attribute_value | string |  |   Sales 
action_result.parameter.user_id | string |  `azure user principal name`  `azure object id`  `email`  |   user@test.onmicrosoft.com 
action_result.data | string |  |  
action_result.summary.status | string |  |   Successfully enabled user user@test.onmicrosoft.com 
action_result.message | string |  |   Status: Successfully enabled user user@test.onmicrosoft.com 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'remove user'
Remove a user from a specified group

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group_object_id** |  required  | Object ID of group | string |  `azure group object id` 
**user_id** |  required  | User ID to remove from group | string |  `azure user principal name`  `azure object id`  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.group_object_id | string |  `azure group object id`  |   ddb876b3-603a-437b-9814-2d46a2219a1e 
action_result.parameter.user_id | string |  `azure user principal name`  `azure object id`  `email`  |   17be76d0-35ed-4881-ab62-d2eb73c2ebe3 
action_result.data | string |  |  
action_result.summary.status | string |  |   Successfully removed user from group 
action_result.message | string |  |   Status: Successfully removed user from group 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'add user'
Add a user to the tenant by creating an organizational account

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group_object_id** |  required  | Object ID of group | string |  `azure group object id` 
**user_id** |  required  | User ID to add to group | string |  `azure object id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.group_object_id | string |  `azure group object id`  |   ddb876b3-603a-437b-9814-2d46a2219a1e 
action_result.parameter.user_id | string |  `azure object id`  |   17be76d0-35ed-4881-ab62-d2eb73c2ebe3 
action_result.data | string |  |  
action_result.summary.status | string |  |   Successfully added user to group 
action_result.message | string |  |   Status: Successfully added user to group 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list groups'
List groups in the organization

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.data.\*.deletionTimestamp | string |  |  
action_result.data.\*.description | string |  |   This is for testing purpose 
action_result.data.\*.dirSyncEnabled | string |  |  
action_result.data.\*.displayName | string |  |   Test-site 
action_result.data.\*.lastDirSyncTime | string |  |  
action_result.data.\*.mail | string |  `email`  |   Test-site@test.onmicrosoft.com 
action_result.data.\*.mailEnabled | boolean |  |   True  False 
action_result.data.\*.mailNickname | string |  |   Test-site 
action_result.data.\*.objectId | string |  `azure object id`  |   2a201c95-101b-42d9-a7af-9a2fdf8193f1 
action_result.data.\*.objectType | string |  |   Group 
action_result.data.\*.odata.type | string |  |   Microsoft.DirectoryServices.Group 
action_result.data.\*.onPremisesDomainName | string |  `domain`  |  
action_result.data.\*.onPremisesNetBiosName | string |  |  
action_result.data.\*.onPremisesSamAccountName | string |  |  
action_result.data.\*.onPremisesSecurityIdentifier | string |  |  
action_result.data.\*.proxyAddresses | string |  |   SMTP:test-h@test.onmicrosoft.com 
action_result.data.\*.securityEnabled | boolean |  |   True  False 
action_result.summary.num_groups | numeric |  |   7 
action_result.message | string |  |   Num groups: 7 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get group'
Get information about a group

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**object_id** |  required  | Object ID of group | string |  `azure object id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.object_id | string |  `azure object id`  |   ddb876b3-603a-437b-9814-2d46a2219a1e 
action_result.data.\*.deletionTimestamp | string |  |  
action_result.data.\*.description | string |  |   This is the office 365 group 
action_result.data.\*.dirSyncEnabled | string |  |  
action_result.data.\*.displayName | string |  |   o365group 
action_result.data.\*.lastDirSyncTime | string |  |  
action_result.data.\*.mail | string |  `email`  |   bc7f9cabe@test.onmicrosoft.com 
action_result.data.\*.mailEnabled | boolean |  |   True  False 
action_result.data.\*.mailNickname | string |  |   bc7f9cabe 
action_result.data.\*.objectId | string |  `azure object id`  |   ddb876b3-603a-437b-9814-2d46a2219a1e 
action_result.data.\*.objectType | string |  |   Group 
action_result.data.\*.odata.metadata | string |  |   https://graph.windows.net/1t309est-db6c-4tes-t1d2-12bf3456d78d/$metadata#directoryObjects/@Element 
action_result.data.\*.odata.type | string |  |   Microsoft.DirectoryServices.Group 
action_result.data.\*.onPremisesDomainName | string |  `domain`  |  
action_result.data.\*.onPremisesNetBiosName | string |  |  
action_result.data.\*.onPremisesSamAccountName | string |  |  
action_result.data.\*.onPremisesSecurityIdentifier | string |  |  
action_result.data.\*.proxyAddresses | string |  |   SMTP:bc7f9cabe@test.onmicrosoft.com 
action_result.data.\*.securityEnabled | boolean |  |   True  False 
action_result.summary.display_name | string |  |   o365group 
action_result.message | string |  |   Display name: o365group 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list group members'
List the members in a group

Type: **investigate**  
Read only: **True**

<p>Pagination is not implemented for this action as this endpoint does not support pagination. Here is the <b><a href='https://docs.microsoft.com/en-us/previous-versions/azure/ad/graph/howto/azure-ad-graph-api-supported-queries-filters-and-paging-options' target='_blank'>Documentation</a></b> for the same.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group_object_id** |  required  | Object ID of group | string |  `azure object id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.group_object_id | string |  `azure object id`  |   ebcd3130-55a1-4cbf-81b2-86408ff21203 
action_result.data.\*.displayName | string |  |   Firstname Lastname 
action_result.data.\*.objectId | string |  `azure object id`  |   17be76d0-35ed-4881-ab62-d2eb73c2ebe3 
action_result.summary.num_members | numeric |  |   3 
action_result.message | string |  |   Num members: 3 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'validate group'
Returns true if a user is in a group; otherwise, false

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group_object_id** |  required  | Object ID of group | string |  `azure group object id` 
**user_id** |  required  | User ID to validate | string |  `azure user principal name`  `azure object id`  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.group_object_id | string |  `azure group object id`  |   ebcd3130-55a1-4cbf-81b2-86408ff21203 
action_result.parameter.user_id | string |  `azure user principal name`  `azure object id`  `email`  |   user@test.onmicrosoft.com 
action_result.data.\*.user_in_group | boolean |  |   True  False 
action_result.summary.user_in_group | boolean |  |   True  False 
action_result.message | string |  |   User in group: True 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list directory roles'
List the directory roles in a tenant

Type: **investigate**  
Read only: **True**

<p>Pagination is not implemented for this action as this endpoint does not support pagination. Here is the <b><a href='https://docs.microsoft.com/en-us/previous-versions/azure/ad/graph/howto/azure-ad-graph-api-supported-queries-filters-and-paging-options' target='_blank'>Documentation</a></b> for the same.</p>

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.data.\*.deletionTimestamp | string |  |  
action_result.data.\*.description | string |  |   Can read basic directory information. For granting access to applications, not intended for users. 
action_result.data.\*.displayName | string |  |   Directory Readers 
action_result.data.\*.isSystem | boolean |  |   True  False 
action_result.data.\*.objectId | string |  `azure object id`  |   02b238cb-0d15-454b-aae6-0e94993a3207 
action_result.data.\*.objectType | string |  |   Role 
action_result.data.\*.odata.type | string |  |   Microsoft.DirectoryServices.DirectoryRole 
action_result.data.\*.roleDisabled | boolean |  |   True  False 
action_result.data.\*.roleTemplateId | string |  `azure role template id`  |   88d8e3e3-8f55-4a1e-953a-9b9898b8876b 
action_result.summary.num_directory_roles | numeric |  |   9 
action_result.message | string |  |   Num directory roles: 9 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'generate token'
Generate a token or regenerates token when the token expires

Type: **generic**  
Read only: **False**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Token generated 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 