[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2023 Splunk Inc."
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
