#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import jwt
import uuid
import requests
import json
import re
import os
from datetime import datetime, timedelta
# disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
TOKEN_TIMEOUT = 300  # 5 minutes

URI_AUTH = 'auth/v2/token'
URI_DEVICES = 'devices/v2'
URI_POLICIES = 'policies/v2'
URI_ZONES = 'zones/v2'
URI_THREATS = 'threats/v2'
URI_LISTS = 'globallists/v2'
URI_RULES = 'rules/v2'
URI_OPTICS_RULESET = 'rulesets/v2'
URI_VALIDATE = 'rules/v2/validate'
URI_TESTING = 'rulesets/v2/88e8b05b-a6f9-4239-825b-bcdf835ff78b'

SCOPE_DEVICE_LIST = 'device:list'
SCOPE_DEVICE_READ = 'device:read'
SCOPE_DEVICE_UPDATE = 'device:update'
SCOPE_DEVICE_THREAT_LIST = 'device:threatlist'
SCOPE_POLICY_LIST = 'policy:list'
SCOPE_POLICY_READ = 'policy:read'
SCOPE_ZONE_CREATE = 'zone:create'
SCOPE_ZONE_LIST = 'zone:list'
SCOPE_ZONE_READ = 'zone:read'
SCOPE_ZONE_UPDATE = 'zone:update'
SCOPE_THREAT_READ = 'threat:read'
SCOPE_THREAT_DEVICE_LIST = 'threat:devicelist'
SCOPE_THREAT_UPDATE = 'threat:update'
SCOPE_GLOBAL_LIST = 'globallist:list'
SCOPE_THREAT_LIST = 'threat:list'
SCOPE_GLOBAL_LIST_CREATE = 'globallist:create'
SCOPE_GLOBAL_LIST_DELETE = 'globallist:delete'
SCOPE_OPTICS_RULE_DEPLOY = 'opticsruleset:create'
SCOPE_OPTICS_RULE_VALIDATE = 'opticsrule:read'

# GLOBALS
CONFIG_LOAD = open('Cy-Deploy-Config.json', 'r')
CONFIG = json.load(CONFIG_LOAD)
APP_ID = CONFIG.get('APP_ID')
APP_SECRET = CONFIG.get('APP_SECRET')
TID = CONFIG.get('TENANT_ID')
SERVER_URL = "https://protectapi.cylance.com"
STANDARD_RULESET = open('CCD-P1-CAE-Rule_Set.json', 'r')
OPTICS_RULESET = json.load(STANDARD_RULESET)

# HELPERS
def generate_jwt_times():
    """
    Generates the epoch time window in which the token will be valid
    Returns the current timestamp and the timeout timestamp (in that order)
    """
    now = datetime.utcnow()
    timeout_datetime = now + timedelta(seconds=TOKEN_TIMEOUT)
    epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
    epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
    return epoch_time, epoch_timeout


def api_call(uri, method='post', headers={}, body={}, params={}, accept_404=False):
    """
    Makes an API call to the server URL with the supplied uri, method, headers, body and params
    """
    url = '%s/%s' % (SERVER_URL, uri)
    res = requests.request(method, url, headers=headers, data=json.dumps(body), params=params, verify=False)
    if res.status_code < 200 or res.status_code >= 300:
        if res.status_code == 409 and str(res.content).find('already an entry for this threat') != -1:
            raise Warning(res.content)
        if not res.status_code == 404 and not accept_404:
            print(
                'Got status code ' + str(res.status_code) + ' with body ' + str(res.content) + ' with headers ' + str(
                    res.headers))
    return json.loads(res.text) if res.text else res.ok


def get_authentication_token(scope=None):
    """
    Generates a JWT authorization token with an optional scope and queries the API for an access token
    Returns the received API access token
    """
    # Generate token ID
    token_id = str(uuid.uuid4())

    # Generate current time & token timeout
    epoch_time, epoch_timeout = generate_jwt_times()
    # Token claims
    claims = {
        'exp': epoch_timeout,
        'iat': epoch_time,
        'iss': 'http://cylance.com',
        'sub': APP_ID,
        'tid': TID,
        'jti': token_id
    }

    if scope:
        claims['scp'] = scope

    # Encode the token
    encoded = jwt.encode(claims, APP_SECRET, algorithm='HS256').decode('utf-8')
    payload = {'auth_token': encoded}
    headers = {'Content-Type': 'application/json; charset=utf-8'}
    res = api_call(method='post', uri=URI_AUTH, body=payload, headers=headers)
    return res['access_token']

def apply_optics_ruleset(rules):
    access_token = get_authentication_token(scope=None)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }

    
    res = api_call(uri=URI_OPTICS_RULESET, method='post', body=rules, headers=headers)

    return res

def main():
    apply_optics_ruleset(OPTICS_RULESET)



if __name__ == "__main__":
    main()