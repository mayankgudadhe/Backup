# (c) 2016, Bill Wang <ozbillwang(at)gmail.com>
# (c) 2017, Marat Bakeev <hawara(at)gmail.com>
# (c) 2018, Michael De La Rue <siblemitcom.mddlr(at)spamgourmet.com>
# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

try:
    import botocore
    import boto3
except ImportError:
    pass  # will be captured by imported HAS_BOTO3

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_native
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display
from ansible.module_utils.six import string_types

from ansible_collections.amazon.aws.plugins.module_utils.ec2 import HAS_BOTO3
from ansible_collections.amazon.aws.plugins.module_utils.ec2 import boto3_tag_list_to_ansible_dict
from ansible_collections.amazon.aws.plugins.module_utils.core import is_boto3_error_code

display = Display()


def _boto3_conn(region, credentials):
    if 'boto_profile' in credentials:
        boto_profile = credentials.pop('boto_profile')
    else:
        boto_profile = None

    try:
        connection = boto3.session.Session(profile_name=boto_profile).client('ssm', region, **credentials)
    except (botocore.exceptions.ProfileNotFound, botocore.exceptions.PartialCredentialsError):
        if boto_profile:
            try:
                connection = boto3.session.Session(profile_name=boto_profile).client('ssm', region)
            # FIXME: we should probably do better passing on of the error information
            except (botocore.exceptions.ProfileNotFound, botocore.exceptions.PartialCredentialsError):
                raise AnsibleError("Insufficient credentials found.")
        else:
            raise AnsibleError("Insufficient credentials found.")
    return connection


class LookupModule(LookupBase):
    def run(self, tags, variables=None, boto_profile=None, aws_profile=None,
            aws_secret_key=None, aws_access_key=None, aws_security_token=None, region=None,
            decrypt=True, on_missing="skip",
            on_denied="skip"):
        '''
            :arg terms: a list of lookups to run.
                e.g. ['parameter_name', 'parameter_name_too' ]
            :kwarg variables: ansible variables active at the time of the lookup
            :kwarg aws_secret_key: identity of the AWS key to use
            :kwarg aws_access_key: AWS secret key (matching identity)
            :kwarg aws_security_token: AWS session key if using STS
            :kwarg decrypt: Set to True to get decrypted parameters
            :kwarg region: AWS region in which to do the lookup
            :kwarg bypath: Set to True to do a lookup of variables under a path
            :kwarg recursive: Set to True to recurse below the path (requires bypath=True)
            :kwarg on_missing: Action to take if the SSM parameter is missing
            :kwarg on_denied: Action to take if access to the SSM parameter is denied
            :returns: A list of parameter values or a list of dictionaries if bypath=True.
        '''

        if not HAS_BOTO3:
            raise AnsibleError('botocore and boto3 are required for aws_ssm lookup.')

        # validate arguments 'on_missing' and 'on_denied'
        if on_missing is not None and (not isinstance(on_missing, string_types) or on_missing.lower() not in ['error', 'warn', 'skip']):
            raise AnsibleError('"on_missing" must be a string and one of "error", "warn" or "skip", not %s' % on_missing)
        if on_denied is not None and (not isinstance(on_denied, string_types) or on_denied.lower() not in ['error', 'warn', 'skip']):
            raise AnsibleError('"on_denied" must be a string and one of "error", "warn" or "skip", not %s' % on_denied)

        ret = []
        ssm_dict = {}

        credentials = {}
        if aws_profile:
            credentials['boto_profile'] = aws_profile
        else:
            credentials['boto_profile'] = boto_profile
        credentials['aws_secret_access_key'] = aws_secret_key
        credentials['aws_access_key_id'] = aws_access_key
        credentials['aws_session_token'] = aws_security_token

        client = _boto3_conn(region, credentials)

        ssm_dict['WithDecryption'] = decrypt
        # ssm_dict['Recursive'] = recursive
        filters = tags

        try:
            response = client.describe_parameters(
               ParameterFilters=filters
            )
        except botocore.exceptions.ClientError as e:
            raise AnsibleError("SSM lookup exception: {0}".format(to_native(e)))

        for term in response['Parameters']:
            ret.append(self.get_parameter_value(client, ssm_dict, term['Name'], on_missing.lower(), on_denied.lower()))

        

        return ret


    def get_parameter_value(self, client, ssm_dict, term, on_missing, on_denied):
        ssm_dict["Name"] = term
        try:
            response = client.get_parameter(**ssm_dict)
                        
            return dict(name=term,value=response['Parameter']['Value'])
        except is_boto3_error_code('ParameterNotFound'):
            if on_missing == 'error':
                raise AnsibleError("Failed to find SSM parameter %s (ResourceNotFound)" % term)
            elif on_missing == 'warn':
                self._display.warning('Skipping, did not find SSM parameter %s' % term)
        except is_boto3_error_code('AccessDeniedException'):  # pylint: disable=duplicate-except
            if on_denied == 'error':
                raise AnsibleError("Failed to access SSM parameter %s (AccessDenied)" % term)
            elif on_denied == 'warn':
                self._display.warning('Skipping, access denied for SSM parameter %s' % term)
        except botocore.exceptions.ClientError as e:  # pylint: disable=duplicate-except
            raise AnsibleError("SSM lookup exception: {0}".format(to_native(e)))
        return None