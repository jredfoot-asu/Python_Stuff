#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import jwt
import uuid
import requests
import json
import re
import os
from datetime import datetime, timedelta
import csv
import time
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
URI_VALIDATE = 'rules/v2/validate'
URI_RULESET = 'rulesets/v2'
URI_TESTING = '/rulesets/v2/default'
URI_Users = 'users/v2'
URI_OPTICS_RULESET = 'rulesets/v2'

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
SCOPE_OPITCS_RULESET = 'opticsruleset:list'
SCOPE_OPTICS_CREATE_RULESET = 'opticsruleset:create'
SCOPE_GLOBAL_LIST_CREATE = 'globallist:create'
SCOPE_GLOBAL_LIST_DELETE = 'globallist:delete'
SCOPE_OPTICS_RULE_DEPLOY = 'opticsrule:create'
SCOPE_OPTICS_RULE_VALIDATE = 'opticsrule:read'


# GLOBALS
CONFIG_LOAD = open('Cy-Deploy-Config.json', 'r')
CONFIG = json.load(CONFIG_LOAD)
APP_ID = CONFIG.get('APP_ID')
APP_SECRET = CONFIG.get('APP_SECRET')
TID = CONFIG.get('TENANT_ID')
SERVER_URL = "https://protectapi.cylance.com"
POLICY_LOAD = open('Baseline_Policy_Creation.json', 'r')
APPLY_POLICY = json.load(POLICY_LOAD)
DEFAULT_RULES = open('default_rules.json', 'r')
DEFAULT_RULES_OPEN = json.load(DEFAULT_RULES)
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

def post_create_new_policy(policy, page=None, page_size=None):
    access_token = get_authentication_token(scope=None)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }

    #uri = '%s/%s' % (URI_POLICIES)
    res = api_call(uri=URI_POLICIES, method='post', body=policy, headers=headers)
    #res.post('Test_Policy_Creation.json')
    return res

def get_users():
    params = {}
    params['page'] = 1
    params['page_size'] = 200    
    access_token = get_authentication_token()
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }
    res = api_call(uri=URI_Users, method='GET', headers=headers, params=params)
    #print(json.dumps(res, indent=4))
    return res

def get_user_id():
    user = get_users()
    for user in user['page_items']:
        #print(user['id'])
        return user['id']

def update_user_id_policy():
    user_id = get_user_id()
    Test_Policy = open('Baseline_Policy.json', 'r')
    Policy = json.load(Test_Policy)
    Test_Policy.close()
    New_Policy = {
    "user_id": user_id,
    "policy": Policy,
    }
    update_policy_id = open('Baseline_Policy_Creation.json', 'w')


    # json.dump(New_Policy, update_policy_id, indent=4)
    # update_policy_id.close()
    return json.dump(New_Policy, update_policy_id, indent=4)

def rule_deploy():
    directory = os.getcwd() + "//rules//"
    for entry in os.scandir(directory):
        if entry.path.endswith(".json"):
            with open(entry.path) as file:
                rule = json.load(file)
                validated_rule = rule_validator(rule)
                print('Result: ' + str(validated_rule) + ' Rule: ' + rule['Name'] + '\n')
                if validated_rule['valid'] == True:
                    rule_deploy_request(rule)

def rule_deploy_request(rule):
    access_token = get_authentication_token()
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }
    body = rule

    res = api_call(uri=URI_RULES, method='POST', headers=headers, body=body)

    return res

def rule_validator(rule):
    
    access_token = get_authentication_token()
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }

    res = api_call(uri=URI_VALIDATE, method='POST', headers=headers, body=rule)

    return res

def get_rulesets():
    f = open('default_rules.json', 'w')
    params = {}

    params['page'] = 1
    params['page_size'] = 200
    
    access_token = get_authentication_token()
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }

    res = api_call(uri=URI_TESTING, method='GET', headers=headers, params=params)

    json.dump(res, f, indent=4)
    print('Rules have been retrieved.')
    return res

def create_optics_json():
    STANDARD_RULE_LIST = open('CCD-P1-CAE-Rule_Set.json', 'w')

    Rule_ID_List = [
        '12c39fcb-38bb-4d96-a927-b3231e2449dc',
        '159f6dc9-226c-4356-8969-c10a7910fd17',
        '2e6d4a19-1b43-4d1e-9473-d6c81ee9366c',
        '3cc71578-2b42-40fa-8af3-1a499d2c63ed',
        '4f060a43-a176-494c-abe3-781e08d01d8b',
        '51ddf265-e285-4ddc-bf11-2e0a3da3cb2d',
        '5301c938-8825-45a8-9a5a-1b9a5937c1c6',
        '531e2c9a-3510-451e-a49b-c7ff5fd7ff44',
        '59d2531d-560d-4cde-8cf1-44dfbd5151ee',
        '5b34162a-1365-439e-91af-d045d338cc4c',
        '5c1515b1-06a1-4f31-96cc-124e0f3703cf',
        '6d7c7efe-acdb-4c04-8de4-7881f8c6cfb6',
        '754ac053-e78a-4ae2-9faa-e78c1ef8c6bd',
        '8f18d849-1594-411d-bba0-d855f003f0d6',
        '8f8d4f8e-3da1-4287-a199-2d4c919a0fc2',
        '94902d1d-a3e3-445f-97d7-97131525d473',
        '98320025-9a7e-48f9-b3cf-e19ed63b0952',
        'a42579af-dd32-4ee5-b760-4b36e347c494',
        'b72634fe-8063-4288-94c1-8076425eb431',
        'b79b40b2-dfa4-49ab-a2ff-2ca022ec2a19',
        'bb2aa3d0-a821-49d7-bd38-bb86a7b1d4a8',
        'c0be2883-d819-4963-8fd1-66dcb70cdbbf',
        'ca868cdf-d067-4006-aa5c-e582425c2949',
        'cc9c3d29-d668-48ad-be04-ec1c667e5769',
        'cf43f8e9-c0a3-4936-94ec-ed66ef974c4a',
        'dd64897b-5cbf-4df3-beca-ec17c18add71',
        'e3f89778-212e-4451-8e94-62af27e2e40e',
        'e94c549c-2fde-453d-a491-b7f732176de0',
        'ecd58ac3-16f5-4c50-ad65-bd83637c8446',
        'd0b77149-d848-47aa-a47c-ef30f7163550',
        'e318bf48-4862-476a-a8ce-084d98e14927',
        '26874384-989c-4962-bc5f-bca0da4b8bb1',
        '6d18c0f6-4697-475e-a194-3a229dfe2f97',
        '83d600a8-f2f5-47e7-a9cd-f0f8e7a7cc17',
        '86134ce8-e329-4e65-921b-e8e9737c7739',
        '8c9ab464-0962-4245-816d-9e933500e1d1',
        'c764e522-7113-4e17-9a39-57cd9b68728c',
        'c9bd9366-a526-41e7-934e-5a8e73b5b252',
        'de164310-1d04-4986-93af-90c5ecb559b0',
        'e45348cc-013a-497a-b1bd-dd2f2a6a3a7f',
        'e5535380-69cb-4c02-836d-f0958bf1061d',
        'f11a76b7-623c-41d5-b726-ce4e22dd9f44',
        '5f9ecb98-420d-4388-90bb-06f50e358ccd',
        '744b850f-c5b5-4ad9-9101-09cba686688f',
        '95dd0545-04ea-4e3b-b591-1d0bfcff0eee',
        'a88bdf1d-3944-45d9-959f-adca8abcbe2b',
        '008ece50-49af-472a-b0d8-3c3700883736',
        '25503624-c696-4f4a-99e2-8ca0d0ea745d',
        '30c95fe5-799b-434e-bf9b-4aa8c8bb829d',
        '9d4347ca-b389-49b5-9807-0820d01c029a',
        'bffb0255-ef08-4196-811b-73da0298f1e8',
        'cdcc1f85-63de-4de5-9c55-370b07e3a218',
        'd8bafee5-ad16-4648-9150-93b1f2f19ff1',
        '1667486d-bc70-4976-9595-9212264571ce',
        '1c5f0ff1-9b8c-4fb4-b7e9-b5ccda6b5235',
        '3ff41a4f-6ec3-42be-a6d8-79b7323c3b7d',
        '41bba187-6aad-4188-9358-74bd16de5fee',
        '5e5b01a7-2bdf-49c9-a58b-82703706a84d',
        '8e91ace0-0504-4662-90b9-f9dd2237cb1b',
        'aabf8025-1817-4acd-aa53-afbae2e3038d',
        'b09b9af5-b449-4e2a-b938-017850c0046f',
        'b9d31692-0417-493f-aa7e-bfc50a383543',
        'c40b7f38-8c4d-4b63-abf8-a7d757c95bf4',
        'd51e1272-5aec-4a22-b037-ae82a98eb93f',
        'ef8bf438-b90e-4fe9-a525-7d1bd5b1ee9f',
        '1c539347-0da0-43d2-8ef6-75dc37546daf',
        '2d398558-5956-49c2-a6a3-bfba6b5a6230',
        '353068f1-0b86-4da6-8541-87735dd50180'
    ]


    with open('default_rules.json') as d:
        data = json.load(d)
        #print(data)


    enabled = []
    enabled_rules = {
            "name": "CCD-P1-CAE-Rule-Set",
            "description": "Standard Rule Set For All Clients",
            "notification_message": "",
            "category": "Custom",
            "SchemaVersion": 1,
            "Version": 1,
            "rules": [] #all lines previous create the json header. This pulls from a file to create the rest of the json to upload.
        }
    for rule in data['rules']:
        if rule['category'] == "Custom":
            Rule_ID_List.append(rule['detection_rule_id'])
        if rule['detection_rule_id'] in Rule_ID_List:
            enabled.append(rule['detection_rule_id'])
            rule['enabled'] = True
            enabled_rules['rules'].append(rule)
        else:
            rule['enabled'] = False
            enabled_rules['rules'].append(rule)

    OPTICS_RULESET = json.dump(enabled_rules, STANDARD_RULE_LIST, indent=4)

def apply_optics_ruleset(rules):
    access_token = get_authentication_token(scope=None)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }

    
    res = api_call(uri=URI_OPTICS_RULESET, method='post', body=rules, headers=headers)
    print('Ruleset has been applied to the tenant.')
    return res

def main():
    def policy():
        input('Are you ready to create the Baseline Policy and deploy the custom OPTICS Ruleset? If you wish to proceed, press "Y": ')
        if input == 'y' or 'Y':
            update_user_id_policy()
            post_create_new_policy(APPLY_POLICY)
            rule_deploy()
        else:
            print('Wrong selection please try again.')
    def get_ruleset_with_custom():
        input('Now, we need to pull down a completed list of rules so that we can turn them on. Are you read to proceed? If yes, press "Y": ')
        if input == 'y' or 'Y':
            get_rulesets()
        else: 
            print('The input was not correct. You will need to start this process over.')
    def create_optics_ruleset_json():
        input('Press Y to proceed in creating the standard OPTICS ruleset json to apply to the account: ')
        if input == 'y' or 'Y':
            create_optics_json()
        else:
            print('Wrong selection please press Y.')
    def create_optics_ruleset():
        input('Press Y to procceed in applying the ruleset json to the tenant: ')
        if input == 'y' or 'Y':
            apply_optics_ruleset(OPTICS_RULESET)
        else:
            print('Wrong selection please press Y.')
    
    policy()
    get_ruleset_with_custom()
    create_optics_ruleset_json()
    create_optics_ruleset()



if __name__ == "__main__":
    main()
