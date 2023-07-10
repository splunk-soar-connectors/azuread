# File: azureadgraph_connector.py
#
# Copyright (c) 2019-2022 Splunk Inc.
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
#
#
# Phantom App imports
import grp
import json
import os
import pwd
import re
import sys
import time

import encryption_helper
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup, UnicodeDammit
from django.http import HttpResponse
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from azureadgraph_consts import *

try:
    import urllib.parse as urlparse
except ImportError:
    import urllib

    import urlparse

TC_FILE = "oauth_task.out"
# SERVER_TOKEN_URL = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token"
MSGRAPH_API_URL = "https://graph.microsoft.com/v1.0"
AZUREADGRAPH_API_URL = "https://graph.windows.net"
MAX_END_OFFSET_VAL = 2147483646


def _handle_login_redirect(request, key):
    """ This function is used to redirect login request to microsoft login page.

    :param request: Data given to REST endpoint
    :param key: Key to search in state file
    :return: response authorization_url/admin_consent_url
    """

    asset_id = request.GET.get('asset_id')
    if not asset_id:
        return HttpResponse('ERROR: Asset ID not found in URL', content_type="text/plain", status=400)
    state = _load_app_state(asset_id)
    if not state:
        return HttpResponse('ERROR: Invalid asset_id', content_type="text/plain", status=400)
    url = state.get(key)
    if not url:
        return HttpResponse('App state is invalid, {key} not found.'.format(key=key), content_type="text/plain", status=400)
    response = HttpResponse(status=302)
    response['Location'] = url
    return response


def _load_app_state(asset_id, app_connector=None):
    """ This function is used to load the current state file.

    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: state: Current state file as a dictionary
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print('In _load_app_state: Invalid asset_id')
        return {}

    app_dir = os.path.dirname(os.path.abspath(__file__))
    state_file = '{0}/{1}_state.json'.format(app_dir, asset_id)
    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print('In _load_app_state: Invalid asset_id')
        return {}

    state = {}
    try:
        with open(real_state_file_path, 'r') as state_file_obj:
            state_file_data = state_file_obj.read()
            state = json.loads(state_file_data)
    except Exception as e:
        if app_connector:
            app_connector.debug_print('In _load_app_state: Exception: {0}'.format(str(e)))

    if app_connector:
        app_connector.debug_print('Loaded state: ', state)

    return state


def _save_app_state(state, asset_id, app_connector):
    """ This function is used to save current state in file.

    :param state: Dictionary which contains data to write in state file
    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: status: phantom.APP_SUCCESS
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print('In _save_app_state: Invalid asset_id')
        return {}

    app_dir = os.path.split(__file__)[0]
    state_file = '{0}/{1}_state.json'.format(app_dir, asset_id)

    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print('In _save_app_state: Invalid asset_id')
        return {}

    if app_connector:
        app_connector.debug_print('Saving state: ', state)

    try:
        with open(real_state_file_path, 'w+') as state_file_obj:
            state_file_obj.write(json.dumps(state))
    except Exception as e:
        if app_connector:
            app_connector.error_print('Unable to save state file: {0}'.format(str(e)))

    return phantom.APP_SUCCESS


def _handle_login_response(request):
    """ This function is used to get the login response of authorization request from microsoft login page.

    :param request: Data given to REST endpoint
    :return: HttpResponse. The response displayed on authorization URL page
    """

    asset_id = request.GET.get('state')
    if not asset_id:
        return HttpResponse('ERROR: Asset ID not found in URL\n{}'.format(json.dumps(request.GET)), content_type="text/plain", status=400)

    # Check for error in URL
    error = request.GET.get('error')
    error_description = request.GET.get('error_description')

    # If there is an error in response
    if error:
        message = 'Error: {0}'.format(error)
        if error_description:
            message = '{0} Details: {1}'.format(message, error_description)
        return HttpResponse('Server returned {0}'.format(message), content_type="text/plain", status=400)

    code = request.GET.get('code')
    admin_consent = request.GET.get('admin_consent')

    # If none of the code or admin_consent is available
    if not (code or admin_consent):
        return HttpResponse('Error while authenticating\n{0}'.format(json.dumps(request.GET)), content_type="text/plain", status=400)

    state = _load_app_state(asset_id)

    # If value of admin_consent is available
    if admin_consent:
        if admin_consent == 'True':
            admin_consent = True
        else:
            admin_consent = False

        state['admin_consent'] = admin_consent
        _save_app_state(state, asset_id, None)

        # If admin_consent is True
        if admin_consent:
            return HttpResponse('Admin Consent received. Please close this window.', content_type="text/plain")
        return HttpResponse('Admin Consent declined. Please close this window and try again later.', content_type="text/plain", status=400)

    # If value of admin_consent is not available, value of code is available
    try:
        state['code'] = AzureADGraphConnector().encrypt_state(code, "code")
        state[MS_AZURE_STATE_IS_ENCRYPTED] = True
    except Exception as e:
        return HttpResponse("{}: {}".format(MS_AZURE_DECRYPTION_ERR, str(e)), content_type="text/plain", status=400)

    _save_app_state(state, asset_id, None)

    return HttpResponse('Code received. Please close this window, the action will continue to get new token.', content_type="text/plain")


def _handle_rest_request(request, path_parts):
    """ Handle requests for authorization.

    :param request: Data given to REST endpoint
    :param path_parts: parts of the URL passed
    :return: dictionary containing response parameters
    """

    if len(path_parts) < 2:
        return HttpResponse('error: True, message: Invalid REST endpoint request', content_type="text/plain", status=400)

    call_type = path_parts[1]

    # To handle admin_consent request in get_admin_consent action
    if call_type == 'admin_consent':
        return _handle_login_redirect(request, 'admin_consent_url')

    # To handle authorize request in test connectivity action
    if call_type == 'start_oauth':
        return _handle_login_redirect(request, 'admin_consent_url')

    # To handle response from microsoft login page
    if call_type == 'result':
        return_val = _handle_login_response(request)
        asset_id = request.GET.get('state')
        if asset_id and asset_id.isalnum():
            app_dir = os.path.dirname(os.path.abspath(__file__))
            auth_status_file_path = '{0}/{1}_{2}'.format(app_dir, asset_id, TC_FILE)
            real_auth_status_file_path = os.path.abspath(auth_status_file_path)
            if not os.path.dirname(real_auth_status_file_path) == app_dir:
                return HttpResponse("Error: Invalid asset_id", content_type="text/plain", status=400)
            open(auth_status_file_path, 'w').close()
            try:
                uid = pwd.getpwnam('apache').pw_uid
                gid = grp.getgrnam('phantom').gr_gid
                os.chown(auth_status_file_path, uid, gid)
                os.chmod(auth_status_file_path, '0664')
            except Exception:
                pass

        return return_val
    return HttpResponse('error: Invalid endpoint', content_type="text/plain", status=404)


def _get_dir_name_from_app_name(app_name):
    """ Get name of the directory for the app.

    :param app_name: Name of the application for which directory name is required
    :return: app_name: Name of the directory for the application
    """

    app_name = ''.join([x for x in app_name if x.isalnum()])
    app_name = app_name.lower()
    if not app_name:
        app_name = 'app_for_phantom'
    return app_name


class RetVal(tuple):

    def __new__(cls, val1, val2):

        return tuple.__new__(RetVal, (val1, val2))


class AzureADGraphConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AzureADGraphConnector, self).__init__()

        self._state = None
        self._tenant = None
        self._client_id = None
        self._client_secret = None
        self._access_token = None
        self._refresh_token = None
        self._base_url = None
        self.asset_id = self.get_asset_id()

    def encrypt_state(self, encrypt_var, token_name):
        """ Handle encryption of token.

        :param encrypt_var: Variable needs to be encrypted
        :return: encrypted variable
        """
        self.debug_print(MS_AZURE_ENCRYPT_TOKEN.format(token_name))  # nosemgrep
        return encryption_helper.encrypt(encrypt_var, self.asset_id)

    def decrypt_state(self, decrypt_var, token_name):
        """ Handle decryption of token.

        :param decrypt_var: Variable needs to be decrypted
        :return: decrypted variable
        """
        self.debug_print(MS_AZURE_DECRYPT_TOKEN.format(token_name))  # nosemgrep
        if self._state.get(MS_AZURE_STATE_IS_ENCRYPTED):
            return encryption_helper.decrypt(decrypt_var, self.asset_id)
        else:
            return decrypt_var

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """
        try:
            if input_str and self._python_version < 3:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except Exception as e:
            self.error_print("Error occurred while handling python 2to3 compatibility for the input string. Error: {}".format(e))

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = None
        error_msg = ERR_MSG_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception as e:
            self.error_print("Error occured while getting message from exeption. Error: {}".format(e))
            pass

        if not error_code:
            error_text = "Error Message: {}".format(error_msg)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

        return error_text

    def _process_empty_response(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200 or response.status_code == 202 or response.status_code == 204:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, MS_AZURE_ERR_EMPTY_RESPONSE.format(code=response.status_code)),
                      None)

    def _process_html_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                                                                      error_text)

        message = self._handle_py_ver_compat_for_input_str(message.replace('{', '{{').replace('}', '}}'))

        if status_code == 400:
            message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, MS_AZURE_HTML_ERROR)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        """ This function is used to process json response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(error_message)), None)

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        error_message = self._handle_py_ver_compat_for_input_str(response.text.replace('{', '{{').replace('}', '}}'))
        message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                     error_message)

        # Show only error message if available
        if isinstance(resp_json.get('error', {}), dict):
            if resp_json.get('error', {}).get('message'):
                error_message = self._handle_py_ver_compat_for_input_str(resp_json['error']['message'])
                message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                             error_message)
        else:
            error_message = self._handle_py_ver_compat_for_input_str(resp_json['error'])
            message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                         error_message)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        if 'text/javascript' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the API talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # Reset_password returns empty body
        if not response.text and 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, {})

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            response.status_code, self._handle_py_ver_compat_for_input_str(response.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_asset_name(self, action_result):
        """ Get name of the asset using Phantom URL.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), asset name
        """

        asset_id = self.get_asset_id()
        rest_endpoint = MS_AZURE_PHANTOM_ASSET_INFO_URL.format(asset_id=asset_id)
        url = '{}{}'.format(MS_AZURE_PHANTOM_BASE_URL.format(phantom_base_url=self._get_phantom_base_url()), rest_endpoint)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)  # nosemgrep

        if phantom.is_fail(ret_val):
            return ret_val, None

        asset_name = resp_json.get('name')
        if not asset_name:
            return action_result.set_status(phantom.APP_ERROR, 'Asset Name for id: {0} not found.'.format(asset_id)), None
        return phantom.APP_SUCCESS, asset_name

    def _get_phantom_base_url_vmazure(self, action_result):
        """ Get base url of phantom.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        base url of phantom
        """

        url = '{}{}'.format(MS_AZURE_PHANTOM_BASE_URL.format(phantom_base_url=self._get_phantom_base_url()), MS_AZURE_PHANTOM_SYS_INFO_URL)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)  # nosemgrep
        if phantom.is_fail(ret_val):
            return ret_val, None

        phantom_base_url = resp_json.get('base_url').rstrip("/")
        if not phantom_base_url:
            return action_result.set_status(phantom.APP_ERROR, MS_AZURE_BASE_URL_NOT_FOUND_MSG), None
        return phantom.APP_SUCCESS, phantom_base_url

    def _get_app_rest_url(self, action_result):
        """ Get URL for making rest calls.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        URL to make rest calls
        """

        ret_val, phantom_base_url = self._get_phantom_base_url_vmazure(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        ret_val, asset_name = self._get_asset_name(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        self.save_progress('Using Phantom base URL: {0}'.format(phantom_base_url))
        app_json = self.get_app_json()
        app_name = app_json['name']

        app_dir_name = _get_dir_name_from_app_name(app_name)
        url_to_app_rest = '{0}/rest/handler/{1}_{2}/{3}'.format(phantom_base_url, app_dir_name, app_json['appid'],
                                                                asset_name)
        return phantom.APP_SUCCESS, url_to_app_rest

    def _make_rest_call(self, endpoint, action_result, verify=True, headers=None, params=None, data=None, json=None, method="get"):
        """ Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            r = request_func(endpoint, json=json, data=data, headers=headers, verify=verify, params=params)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}"
                                                   .format(error_message)), resp_json)

        return self._process_response(r, action_result)

    def _make_rest_call_helper(self, action_result, endpoint, verify=True, headers=None, params=None, data=None, json=None, method="get"):
        """ Function that helps setting REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        url = "{0}/{1}{2}".format(self._base_url, self._tenant, endpoint)
        if headers is None:
            headers = {}

        token = self._state.get('token', {})
        if not token.get('access_token'):
            ret_val = self._get_token(action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        headers.update({
                'Authorization': 'Bearer {0}'.format(self._access_token),
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            })

        ret_val, resp_json = self._make_rest_call(url, action_result, verify, headers, params, data, json, method)

        # If token is expired, generate a new token
        msg = action_result.get_message()
        if msg and any(failure_message in msg for failure_message in AUTH_FAILURE_MESSAGES):
            self.save_progress("bad token")
            ret_val = self._get_token(action_result)

            headers.update({'Authorization': 'Bearer {0}'.format(self._access_token)})

            ret_val, resp_json = self._make_rest_call(url, action_result, verify, headers, params, data, json, method)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _handle_generate_token(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._get_token(action_result)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self._state['admin_consent'] = True

        return action_result.set_status(phantom.APP_SUCCESS, "Token generated")

    def _handle_test_connectivity(self, param):
        """ Function that handles the test connectivity action, it is much simpler than other action handlers."""

        # Progress
        # self.save_progress("Generating Authentication URL")
        config = self.get_config()
        app_state = {}
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Getting App REST endpoint URL")
        # Get the URL to the app's REST Endpoint, this is the url that the TC dialog
        # box will ask the user to connect to
        ret_val, app_rest_url = self._get_app_rest_url(action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(MS_REST_URL_NOT_AVAILABLE_MSG.format(error=action_result.get_status()))
            return action_result.set_status(phantom.APP_ERROR)

        # create the url that the oauth server should re-direct to after the auth is completed
        # (success and failure), this is added to the state so that the request handler will access
        # it later on
        redirect_uri = "{0}/result".format(app_rest_url)
        app_state['redirect_uri'] = redirect_uri

        self.save_progress(MS_OAUTH_URL_MSG)
        self.save_progress(redirect_uri)

        if self._python_version < 3:
            self._client_id = urllib.quote(self._client_id)
            self._tenant = urllib.quote(self._tenant)
        else:
            self._client_id = urlparse.quote(self._client_id)
            self._tenant = urlparse.quote(self._tenant)

        admin_consent_url_base = "https://login.microsoftonline.com/{0}/oauth2/authorize".format(self._tenant)

        query_params = {
            'client_id': self._client_id,
            'redirect_uri': redirect_uri,
            'state': self.get_asset_id(),
            'scope': MS_AZURE_CODE_GENERATION_SCOPE,
            'resource': urlparse.quote('https://{0}/'.format(AZUREADGRAPH_API_REGION[config.get(MS_AZURE_URL, "Global")]), safe=''),
            'response_type': "code"
        }

        query_string = '&'.join(f'{key}={value}' for key, value in query_params.items())

        admin_consent_url = f'{admin_consent_url_base}?{query_string}'

        app_state['admin_consent_url'] = admin_consent_url

        # The URL that the user should open in a different tab.
        # This is pointing to a REST endpoint that points to the app
        url_to_show = "{0}/start_oauth?asset_id={1}&".format(app_rest_url, self.get_asset_id())

        # Save the state, will be used by the request handler
        _save_app_state(app_state, self.get_asset_id(), self)

        self.save_progress('Please connect to the following URL from a different tab to continue the connectivity process')
        self.save_progress(url_to_show)
        self.save_progress(MS_AZURE_AUTHORIZE_TROUBLESHOOT_MSG)

        time.sleep(5)

        completed = False

        app_dir = os.path.dirname(os.path.abspath(__file__))
        auth_status_file_path = "{0}/{1}_{2}".format(app_dir, self.get_asset_id(), TC_FILE)

        self.save_progress('Waiting for authorization to complete')

        for i in range(0, 40):

            self.send_progress('{0}'.format('.' * (i % 10)))

            if os.path.isfile(auth_status_file_path):
                completed = True
                os.unlink(auth_status_file_path)
                break

            time.sleep(MS_TC_STATUS_SLEEP)

        if not completed:
            self.save_progress("Authentication process does not seem to be completed. Timing out")
            return action_result.set_status(phantom.APP_ERROR)

        # Load the state again, since the http request handlers would have saved the result of the admin consent
        self._state = _load_app_state(self.get_asset_id(), self)

        if not self._state:
            self.save_progress("Authorization not received or not given")
            self.save_progress("Test Connectivity Failed")
            return action_result.set_status(phantom.APP_ERROR)

        # The authentication seems to be done, let's see if it was successful
        self._state['admin_consent'] = self._state.get('admin_consent', False)

        self.save_progress(MS_GENERATING_ACCESS_TOKEN_MSG)
        ret_val = self._get_token(action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress("Getting info about a single user to verify token")
        params = {'api-version': '1.6', '$top': '1'}
        ret_val, response = self._make_rest_call_helper(action_result, "/users", params=params)

        if phantom.is_fail(ret_val):
            self.save_progress("API to get users failed")
            self.save_progress("Test Connectivity Failed")
            return action_result.set_status(phantom.APP_ERROR)

        value = response.get('value')

        if value:
            self.save_progress("Got user info")

        self.save_progress("Test Connectivity Passed")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_users(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        parameters = {
            'api-version': '1.6'
        }
        filter_string = param.get('filter_string')
        if filter_string:
            parameters['$filter'] = filter_string

        endpoint = '/users'

        ret_val = self._handle_pagination(action_result, endpoint, parameters=parameters)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        summary['num_users'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_reset_password(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['user_id'])
        temp_password = self._handle_py_ver_compat_for_input_str(param.get('temp_password', ''))
        force_change = param.get('force_change', True)

        parameters = {'api-version': '1.6'}

        data = {
            'passwordProfile': {
                'forceChangePasswordNextLogin': force_change
            }
        }
        if temp_password != '':
            data['passwordProfile']['password'] = temp_password

        endpoint = '/users/{0}'.format(user_id)

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=parameters, json=data, method='patch')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        summary['status'] = "Successfully reset password for {}".format(user_id)

        # An empty response indicates success. No response body is returned.
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_enable_user(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['user_id'])
        parameters = {'api-version': '1.6'}

        data = {
            "accountEnabled": True
        }

        endpoint = '/users/{}'.format(user_id)
        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=parameters, json=data, method='patch')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['status'] = "Successfully enabled user {}".format(user_id)

        # An empty response indicates success. No response body is returned.
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_invalidate_tokens(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['user_id'])
        parameters = {'api-version': '1.6'}
        endpoint = '/users/{0}/invalidateAllRefreshTokens'.format(user_id)

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=parameters, method='post')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['status'] = "Successfully disabled tokens"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_disable_user(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['user_id'])
        parameters = {'api-version': '1.6'}

        data = {
            "accountEnabled": False
        }

        endpoint = '/users/{}'.format(user_id)
        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=parameters, json=data, method='patch')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['status'] = "Successfully disabled user {}".format(user_id)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_user_attributes(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param.get('user_id'))
        parameters = {'api-version': '1.6'}
        if user_id:
            endpoint = '/users/{}'.format(user_id)
        else:
            endpoint = '/users'

        ret_val = self._handle_pagination(action_result, endpoint, parameters=parameters)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        if user_id:
            summary['status'] = "Successfully retrieved attributes for user {}".format(user_id)
            response = action_result.get_data()[0]
            summary['user_enabled'] = response.get('accountEnabled')
        else:
            summary['status'] = "Successfully retrieved user attributes"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_set_user_attribute(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['user_id'])
        attribute = self._handle_py_ver_compat_for_input_str(param['attribute'])
        attribute_value = self._handle_py_ver_compat_for_input_str(param['attribute_value'])
        parameters = {'api-version': '1.6'}

        data = {
            attribute: attribute_value
        }

        endpoint = '/users/{}'.format(user_id)
        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=parameters, json=data, method='patch')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        summary['status'] = "Successfully updated user attribute"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_user(self, param):

        config = self.get_config()
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        object_id = self._handle_py_ver_compat_for_input_str(param['group_object_id'])
        user_id = self._handle_py_ver_compat_for_input_str(param['user_id'])

        parameters = {
            'api-version': '1.6'
        }

        data = {
            'url': "https://{}/{}/directoryObjects/{}".format(AZUREADGRAPH_API_REGION[config.get(MS_AZURE_URL, "Global")], self._tenant, user_id)
        }

        endpoint = '/groups/{}/$links/members'.format(object_id)
        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=parameters, json=data, method='post')

        summary = action_result.update_summary({})
        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            if 'references already exist for the following modified properties: \'members\'.' in message:
                summary['status'] = "User already in group"
            else:
                return action_result.get_status()
        else:
            summary['status'] = "Successfully added user to group"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_user(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        object_id = self._handle_py_ver_compat_for_input_str(param['group_object_id'])
        user_id = self._handle_py_ver_compat_for_input_str(param['user_id'])

        parameters = {
            'api-version': '1.6'
        }

        endpoint = '/groups/{}/$links/members/{}'.format(object_id, user_id)
        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=parameters, method='delete')

        summary = action_result.update_summary({})
        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            if 'does not exist or one of its queried' in message:
                summary['status'] = "User not in group"
            else:
                return action_result.get_status()
        else:
            summary['status'] = "Successfully removed user from group"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_groups(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        parameters = {'api-version': '1.6'}

        endpoint = '/groups'
        ret_val = self._handle_pagination(action_result, endpoint, parameters=parameters)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        summary['num_groups'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_group(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        object_id = self._handle_py_ver_compat_for_input_str(param['object_id'])
        parameters = {'api-version': '1.6'}

        endpoint = '/groups/{}'.format(object_id)
        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=parameters, method='get')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['display_name'] = response.get('displayName')

        return action_result.set_status(phantom.APP_SUCCESS)

    def get_user_id_map(self, action_result, user=None):
        # Get list of members and using their object IDs, map them to the URLs
        parameters = {'api-version': '1.6'}
        endpoint = '/users'
        if user:
            endpoint = endpoint + '/' + user
        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=parameters, method='get')

        user_id_map = dict()

        if phantom.is_fail(ret_val):
            return ret_val, user_id_map

        if user:
            user_id_map[response.get('objectId')] = response.get('displayName')
        else:
            for user in response.get('value', []):
                user_id_map[user['objectId']] = user['displayName']

        return ret_val, user_id_map

    def _handle_list_group_members(self, param):

        config = self.get_config()
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        object_id = self._handle_py_ver_compat_for_input_str(param['group_object_id'])
        parameters = {'api-version': '1.6'}

        # Returns a list of group members' directory object URLs
        endpoint = '/groups/{}/$links/members'.format(object_id)
        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=parameters, method='get')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # action_result.add_data(response)
        user_object_ids = list()
        for item in response.get('value', []):
            url = item.get('url', '')
            match = re.match(
                AZUREADGRAPH_API_REGEX.format(
                    AZUREADGRAPH_API_REGION[config.get(MS_AZURE_URL, "Global")], self._tenant
                ),
                url
            )
            if match is not None:
                user_object_ids.append(match.group(1))

        user_id_map_ret_val, user_id_map = self.get_user_id_map(action_result)

        # Mapping
        for item in user_object_ids:
            data = {
                'displayName': user_id_map[item],
                'objectId': item
            }
            action_result.add_data(data)

        summary = action_result.update_summary({})
        summary['num_members'] = len(user_object_ids)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_directory_roles(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        parameters = {'api-version': '1.6'}

        endpoint = '/directoryRoles'
        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=parameters, method='get')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        value = response.get('value', [])
        for item in value:
            action_result.add_data(item)

        summary = action_result.update_summary({})
        summary['num_directory_roles'] = len(value)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_validate_group(self, param):

        config = self.get_config()
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        object_id = self._handle_py_ver_compat_for_input_str(param['group_object_id'])
        user_id = self._handle_py_ver_compat_for_input_str(param['user_id'])
        parameters = {'api-version': '1.6'}

        # Returns a list of group members' directory object URLs
        endpoint = '/groups/{}/$links/members'.format(object_id)
        ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=parameters, method='get')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # action_result.add_data(response)
        user_object_ids = list()
        for item in response.get('value', []):
            url = item.get('url', '')
            match = re.match(
                AZUREADGRAPH_API_REGEX.format(
                    AZUREADGRAPH_API_REGION[config.get(MS_AZURE_URL, "Global")], self._tenant
                ),
                url
            )
            if match is not None:
                user_object_ids.append(match.group(1))

        user_id_map_ret_val, user_id_map = self.get_user_id_map(action_result, user=user_id)

        user_in_group = False

        if phantom.is_fail(user_id_map_ret_val):
            return action_result.get_status()
        # Look for user in group
        for item in user_object_ids:
            if user_id_map.get(item):
                user_in_group = True

        action_result.add_data({'user_in_group': user_in_group})
        summary = action_result.update_summary({})
        summary['user_in_group'] = user_in_group

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_token(self, action_result, from_action=False):
        """ This function is used to get a token via REST Call.

        :param action_result: Object of action result
        :param from_action: Boolean object of from_action
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        config = self.get_config()
        data = {
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'grant_type': 'client_credentials',
        }

        req_url = AZUREADGRAPH_SERVER_TOKEN_URLS[config.get(MS_AZURE_URL, "Global")].format(self._tenant)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        if from_action or self._refresh_token is not None:
            data['refresh_token'] = self._refresh_token
            data['grant_type'] = 'refresh_token'
        else:
            data['redirect_uri'] = self._state.get('redirect_uri')
            try:
                data['code'] = self.decrypt_state(self._state.get('code'), "code") if self._state.get('code') else None
            except Exception as e:
                self.error_print("{}: {}".format(MS_AZURE_DECRYPTION_ERR, self._get_error_message_from_exception(e)))
                return action_result.set_status(phantom.APP_ERROR, MS_AZURE_DECRYPTION_ERR)
            data['grant_type'] = 'authorization_code'

        ret_val, resp_json = self._make_rest_call(req_url, action_result, headers=headers, data=data, method='post')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if resp_json.get('id_token'):
            resp_json.pop('id_token')

        self._access_token = resp_json[MS_AZURE_ACCESS_TOKEN_STRING]
        self._refresh_token = resp_json[MS_AZURE_REFRESH_TOKEN_STRING]

        self._state[MS_AZURE_TOKEN_STRING] = resp_json

        return phantom.APP_SUCCESS

    def _handle_pagination(self, action_result, endpoint, parameters=None):
        """
        This action is used to create an iterator that will paginate through responses from called methods.

        :param action_result: Object of ActionResult class
        :param endpoint: REST endpoint that needs to appended to the service address
        :param **kwargs: Dictionary of Input parameters
        """
        # maximum page size
        page_size = MS_AZURE_PAGE_SIZE
        if isinstance(parameters, dict):
            parameters.update({"$top": page_size})
        else:
            parameters = {"$top": page_size}

        while True:

            # make rest call
            ret_val, response = self._make_rest_call_helper(action_result, endpoint, params=parameters, method='get')

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if "value" in response:
                for user in response.get('value', []):
                    action_result.add_data(user)
            else:
                action_result.add_data(response)

            if response.get(MS_AZURE_NEXT_LINK_STRING):
                parsed_url = urlparse.urlparse(response.get(MS_AZURE_NEXT_LINK_STRING))
                try:
                    parameters['$skiptoken'] = urlparse.parse_qs(parsed_url.query).get('$skiptoken')[0]
                except Exception as e:
                    self.error_print("odata.nextLink is {0}".format(response.get(MS_AZURE_NEXT_LINK_STRING)))
                    self.error_print("Error occurred while extracting skiptoken from the odata.nextLink. Error: {}".format(e))
                    break
            else:
                break

        return phantom.APP_SUCCESS

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_users':
            ret_val = self._handle_list_users(param)

        elif action_id == 'reset_password':
            ret_val = self._handle_reset_password(param)

        elif action_id == 'invalidate_tokens':
            ret_val = self._handle_invalidate_tokens(param)

        elif action_id == 'enable_user':
            ret_val = self._handle_enable_user(param)

        elif action_id == 'disable_user':
            ret_val = self._handle_disable_user(param)

        elif action_id == 'list_user_attributes':
            ret_val = self._handle_list_user_attributes(param)

        elif action_id == 'set_user_attribute':
            ret_val = self._handle_set_user_attribute(param)

        elif action_id == 'remove_user':
            ret_val = self._handle_remove_user(param)

        elif action_id == 'add_user':
            ret_val = self._handle_add_user(param)

        elif action_id == 'list_groups':
            ret_val = self._handle_list_groups(param)

        elif action_id == 'get_group':
            ret_val = self._handle_get_group(param)

        elif action_id == 'list_group_members':
            ret_val = self._handle_list_group_members(param)

        elif action_id == 'validate_group':
            ret_val = self._handle_validate_group(param)

        elif action_id == 'list_directory_roles':
            ret_val = self._handle_list_directory_roles(param)

        elif action_id == 'generate_token':
            ret_val = self._handle_generate_token(param)

        return ret_val

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }
            return self.set_status(phantom.APP_ERROR, MS_AZURE_STATE_FILE_CORRUPT_ERR)

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except Exception:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        # get the asset config
        config = self.get_config()

        self._tenant = self._handle_py_ver_compat_for_input_str(config[MS_AZURE_CONFIG_TENANT])
        self._client_id = self._handle_py_ver_compat_for_input_str(config[MS_AZURE_CONFIG_CLIENT_ID])
        self._client_secret = config[MS_AZURE_CONFIG_CLIENT_SECRET]

        self._access_token = self._state.get(MS_AZURE_TOKEN_STRING, {}).get(MS_AZURE_ACCESS_TOKEN_STRING, None)
        if self._state.get(MS_AZURE_STATE_IS_ENCRYPTED) and self._access_token:
            try:
                self._access_token = self.decrypt_state(self._access_token, "access")
            except Exception as e:
                self.error_print("{}: {}".format(MS_AZURE_DECRYPTION_ERR, self._get_error_message_from_exception(e)))
                self._access_token = None

        self._refresh_token = self._state.get(MS_AZURE_TOKEN_STRING, {}).get(MS_AZURE_REFRESH_TOKEN_STRING, None)
        if self._state.get(MS_AZURE_STATE_IS_ENCRYPTED) and self._refresh_token:
            try:
                self._refresh_token = self.decrypt_state(self._refresh_token, "refresh")
            except Exception as e:
                self.error_print("{}: {}".format(MS_AZURE_DECRYPTION_ERR, self._get_error_message_from_exception(e)))
                self._refresh_token = None

        self._base_url = AZUREADGRAPH_API_URLS[config.get(MS_AZURE_URL, "Global")]

        return phantom.APP_SUCCESS

    def finalize(self):

        try:
            if self._state.get(MS_AZURE_TOKEN_STRING, {}).get(MS_AZURE_ACCESS_TOKEN_STRING):
                self._state[MS_AZURE_TOKEN_STRING][MS_AZURE_ACCESS_TOKEN_STRING] = self.encrypt_state(self._access_token, "access")
        except Exception as e:
            self.error_print("{}: {}".format(MS_AZURE_ENCRYPTION_ERR, self._get_error_message_from_exception(e)))
            self._state[MS_AZURE_TOKEN_STRING][MS_AZURE_ACCESS_TOKEN_STRING] = None

        try:
            if self._state.get(MS_AZURE_TOKEN_STRING, {}).get(MS_AZURE_REFRESH_TOKEN_STRING):
                self._state[MS_AZURE_TOKEN_STRING][MS_AZURE_REFRESH_TOKEN_STRING] = self.encrypt_state(self._refresh_token, "refresh")
        except Exception as e:
            self.error_print("{}: {}".format(MS_AZURE_ENCRYPTION_ERR, self._get_error_message_from_exception(e)))
            self._state[MS_AZURE_TOKEN_STRING][MS_AZURE_REFRESH_TOKEN_STRING] = None

        if not self._state.get(MS_AZURE_STATE_IS_ENCRYPTED):
            try:
                if self._state.get('code'):
                    self._state['code'] = self.encrypt_state(self._state['code'], "code")
            except Exception as e:
                self.error_print("{}: {}".format(MS_AZURE_ENCRYPTION_ERR, self._get_error_message_from_exception(e)))
                self._state['code'] = None
            if self._state.get(MS_AZURE_TOKEN_STRING, {}).get("id_token"):
                self._state[MS_AZURE_TOKEN_STRING].pop("id_token")

        # Save the state, this data is saved across actions and app upgrades
        self._state[MS_AZURE_STATE_IS_ENCRYPTED] = True
        self.save_state(self._state)
        _save_app_state(self._state, self.get_asset_id(), self)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=60)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=60)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AzureADGraphConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
