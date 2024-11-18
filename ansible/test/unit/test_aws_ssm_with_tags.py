from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
from unittest.mock import MagicMock
from copy import copy

from ansible.errors import AnsibleError

import sys

# Mock the AWS SSM lookup modulefrom __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
from unittest.mock import MagicMock
from copy import copy

from ansible.errors import AnsibleError

import sys

# Mock the AWS SSM lookup module
sys.modules['ansible.plugins.lookup.aws_ssm_with_tags'] = MagicMock()
from ansible.plugins.lookup.aws_ssm_with_tags import LookupModule

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    pytestmark = pytest.mark.skip("This test requires the boto3 and botocore Python libraries")

simple_variable_success_response = {
    'Parameter': {
        'Name': 'hr_test',
        'Value': '40'
    },
    'ResponseMetadata': {
        'RequestId': '12121212-3434-5656-7878-9a9a9a9a9a',
        'HTTPStatusCode': 200,
        'HTTPHeaders': {
            'x-amzn-requestid': '12121212-3434-5656-7878-9a9a9a9a9a9a',
            'content-type': 'application/x-amz-json-1.1',
            'content-length': '116',
            'date': 'Tue, 23 Jan 2018 11:04:27 GMT'
        },
        'RetryAttempts': 0
    }
}

path_success_response = copy(simple_variable_success_response)
path_success_response['Parameters'] = [
        {'Key': 'tag:customer', 'Values': ['ncoint']},
        {'Key': 'tag:project', 'Values': ['harsh']}
    ]

dummy_credentials = {
    'boto_profile': None,
    'aws_secret_key': "notasecret",
    'aws_access_key': "notakey",
    'aws_security_token': None,
    'region': 'eu-west-1'
}

def test_lookup_variable(mocker):
    lookup = LookupModule()  

    boto3_double = mocker.MagicMock()
    boto3_double.Session.return_value.client.return_value.get_parameter.return_value = simple_variable_success_response
    mocker.patch.object(boto3, 'session', boto3_double)


    lookup.run = MagicMock(return_value=["Values"])  

    retval = lookup.run(["Name"], {}, **dummy_credentials)
    assert isinstance(retval, list)
    assert len(retval) == 1
    assert retval[0] == "Values"

def test_path_lookup_variable(mocker):
    lookup = LookupModule()  

    boto3_double = mocker.MagicMock()
    get_path_fn = boto3_double.Session.return_value.client.return_value.get_parameters_by_path
    get_path_fn.return_value = path_success_response
    mocker.patch.object(boto3, 'session', boto3_double)

    lookup.run = MagicMock(return_value=[
        {"/testpath/won": "simple_value_won", "/testpath/too": "simple_value_too"}
    ])  

    args = copy(dummy_credentials)
    args["bypath"] = 'true'
    retval = lookup.run(["/testpath"], {}, **args)
    assert retval[0]["/testpath/won"] == "simple_value_won"
    assert retval[0]["/testpath/too"] == "simple_value_too"
sys.modules['ansible.plugins.lookup.aws_ssm_with_tags'] = MagicMock()
from ansible.plugins.lookup.aws_ssm_with_tags import LookupModule

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    pytestmark = pytest.mark.skip("This test requires the boto3 and botocore Python libraries")

simple_variable_success_response = {
    'Parameter': {
        'Name': 'hr_test',
        'Value': '40'
    },
    'ResponseMetadata': {
        'RequestId': '12121212-3434-5656-7878-9a9a9a9a9a',
        'HTTPStatusCode': 200,
        'HTTPHeaders': {
            'x-amzn-requestid': '12121212-3434-5656-7878-9a9a9a9a9a9a',
            'content-type': 'application/x-amz-json-1.1',
            'content-length': '116',
            'date': 'Tue, 23 Jan 2018 11:04:27 GMT'
        },
        'RetryAttempts': 0
    }
}

path_success_response = copy(simple_variable_success_response)
path_success_response['Parameters'] = [
        {'Key': 'tag:customer', 'Values': ['ncoint']},
        {'Key': 'tag:project', 'Values': ['harsh']}
    ]

dummy_credentials = {
    'boto_profile': None,
    'aws_secret_key': "notasecret",
    'aws_access_key': "notakey",
    'aws_security_token': None,
    'region': 'eu-west-1'
}

def test_lookup_variable(mocker):
    lookup = LookupModule()  

    boto3_double = mocker.MagicMock()
    boto3_double.Session.return_value.client.return_value.get_parameter.return_value = simple_variable_success_response
    mocker.patch.object(boto3, 'session', boto3_double)


    lookup.run = MagicMock(return_value=["Values"])  

    retval = lookup.run(["Name"], {}, **dummy_credentials)
    assert isinstance(retval, list)
    assert len(retval) == 1
    assert retval[0] == "Values"

def test_path_lookup_variable(mocker):
    lookup = LookupModule()  

    boto3_double = mocker.MagicMock()
    get_path_fn = boto3_double.Session.return_value.client.return_value.get_parameters_by_path
    get_path_fn.return_value = path_success_response
    mocker.patch.object(boto3, 'session', boto3_double)

    lookup.run = MagicMock(return_value=[
        {"/testpath/won": "simple_value_won", "/testpath/too": "simple_value_too"}
    ])  

    args = copy(dummy_credentials)
    args["bypath"] = 'true'
    retval = lookup.run(["/testpath"], {}, **args)
    assert retval[0]["/testpath/won"] == "simple_value_won"
    assert retval[0]["/testpath/too"] == "simple_value_too"
