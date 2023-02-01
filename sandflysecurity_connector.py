#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import json
import sys
from datetime import datetime

# Phantom App imports
import phantom.app as phantom
# Usage of the consts file is recommended
# from sandflysecurity_consts import *
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SandflySecurityConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SandflySecurityConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()

            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("_handle_test_connectivity")

        # make rest call
        headers = dict()
        headers['Accept'] = 'application/json'
        headers['Content-Type'] = 'application/json'
        headers['Authorization'] = 'Bearer ' + self._access_token

        # First get the Sandfly Server version
        ret_val, response = self._make_rest_call(
            '/version', action_result, params=None, headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['version'] = response['version']
        summary['build_date'] = response['build_date']

        # Next get the Sandfly Server license information
        ret_val, response = self._make_rest_call(
            '/license', action_result, params=None, headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        b_valid_license = False
        b_is_expired = False

        # self.save_progress(json.dumps(response, indent=4, sort_keys=True))

        t_customer = response['customer']
        # self.save_progress('Customer Name: {}'.format(t_customer['name']))
        summary['customer_name'] = t_customer['name']

        t_date = response['date']
        # self.save_progress('Expiration Date: {}'.format(t_date['expiry']))
        summary['expiration_date'] = t_date['expiry']

        t_expiry = datetime.strptime( t_date['expiry'], "%Y-%m-%dT%H:%M:%SZ" )
        t_now = datetime.utcnow()

        if t_expiry < t_now:
            b_is_expired = True

        t_features_list = response['limits']['features']
        for f in t_features_list:
            if f == 'splunk_connector':
                b_valid_license = True

        if b_is_expired is True:
            self.save_progress("ERROR: License Expired")
            summary['license_status'] = "Expired"
            return action_result.set_status(phantom.APP_ERROR, "License Expired")

        if b_valid_license is False:
            self.save_progress("ERROR: Invalid License")
            summary['license_status'] = "Invalid"
            return action_result.set_status(phantom.APP_ERROR, "Invalid License")

        summary['license_status'] = 'Valid'

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_scan_host(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        ip_hostname = param['ip_hostname']

        # Optional values should use the .get() function
        b_type_directory = param.get('directory', False)
        b_type_file = param.get('file', False)
        b_type_incident = param.get('incident', False)
        b_type_log = param.get('log', False)
        b_type_policy = param.get('policy', False)
        b_type_process = param.get('process', False)
        b_type_recon = param.get('recon', False)
        b_type_user = param.get('user', False)

        # make rest call
        headers = dict()
        headers['Accept'] = 'application/json'
        headers['Content-Type'] = 'application/json'
        headers['Authorization'] = 'Bearer ' + self._access_token

        myparams = dict()
        myparams['summary'] = 'true'

        ret_val, response = self._make_rest_call(
            '/hosts', action_result, params=myparams, headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # self.save_progress(json.dumps(response, indent=4, sort_keys=True))

        my_host_id = None

        data_list = response['data']
        for item in data_list:
            the_name = item['hostname']
            last_ip = item['last_seen_ip_addr']
            the_id = item['host_id']
            # self.save_progress("{} | {}".format(ip_hostname, the_name))
            if last_ip == ip_hostname:
                my_host_id = the_id
                # self.save_progress("last_ip match: ip_hostname: {} host_id: {}".format(ip_hostname, my_host_id))
                break
            if the_name == ip_hostname:
                my_host_id = the_id
                # self.save_progress("the_name match: ip_hostname: {} host_id: {}".format(ip_hostname, my_host_id))
                break

        # self.save_progress("ip_hostname: {}\nhost_id: {}".format(ip_hostname, my_host_id))

        if my_host_id is None:
            return action_result.set_status(phantom.APP_ERROR, "IP/Hostname [{}] not found".format(ip_hostname))

        headers = dict()
        headers['Accept'] = 'application/json'
        headers['Content-Type'] = 'application/json'
        headers['Authorization'] = 'Bearer ' + self._access_token

        ret_val, response = self._make_rest_call(
            '/sandflies', action_result, params=None, headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        data_list = response['data']

        t_sandfly_list = []
        for item in data_list:
            if item['active'] is True:
                if b_type_directory is True and item['type'] == 'directory':
                    t_sandfly_list.append(item['id'])
                if b_type_file is True and item['type'] == 'file':
                    t_sandfly_list.append(item['id'])
                if b_type_incident is True and item['type'] == 'incident':
                    t_sandfly_list.append(item['id'])
                if b_type_log is True and item['type'] == 'log':
                    t_sandfly_list.append(item['id'])
                if b_type_policy is True and item['type'] == 'policy':
                    t_sandfly_list.append(item['id'])
                if b_type_process is True and item['type'] == 'process':
                    t_sandfly_list.append(item['id'])
                if b_type_recon is True and item['type'] == 'recon':
                    t_sandfly_list.append(item['id'])
                if b_type_user is True and item['type'] == 'user':
                    t_sandfly_list.append(item['id'])

        # self.save_progress(t_sandfly_list)

        if len(t_sandfly_list) == 0:
            return action_result.set_status(phantom.APP_ERROR, "No Sandflies selected for scanning")

        # make rest call
        t_host_ids = [my_host_id]
        scan_payload = { "host_ids": t_host_ids, "sandfly_list": t_sandfly_list }

        # self.save_progress(json.dumps(scan_payload))

        ret_val, response = self._make_rest_call(
            '/scan', action_result, method="post", data=json.dumps(scan_payload), headers=headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        self.save_progress(json.dumps(response))

        # Add the response into the data section
        action_result.add_data(scan_payload)
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'scan_host':
            ret_val = self._handle_scan_host(param)

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config['Sandfly Server URL']
        self._username = config['Username']
        self._password = config['Password']

        try:
            login_url = self._base_url + '/auth/login'

            data = dict()
            data['username'] = self._username
            data['password'] = self._password

            headers = dict()
            headers['Accept'] = 'application/json'
            headers['Content-Type'] = 'application/json'

            r2 = requests.post(login_url, verify=False, data=json.dumps(data), headers=headers)

            if r2.status_code != 200:
                return phantom.APP_ERROR

            json_data = r2.json()
            self._access_token = json_data['access_token']
            self._refresh_token = json_data['refresh_token']

        except Exception as e:
            self.save_progress("ERROR: Unable to get session id - Error: " + str(e))
            return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = SandflySecurityConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SandflySecurityConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)


if __name__ == '__main__':
    main()
