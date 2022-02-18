from elasticsearch import Elasticsearch
import json
import csv
import pandas as pd
import os.path
import time
import threading
import concurrent.futures
from oauth2client.service_account import ServiceAccountCredentials
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from datetime import datetime
import gspread

currentMonth = datetime.now().month
currentYear = datetime.now().year
organization_id = 'aaaaq3'
file_path = './Elastic_API/'

report_month = 0
report_year = 0

if currentMonth == 1:
    report_month = 12
    report_year = currentYear -1
else:
    report_month = currentMonth - 1
    report_year = currentYear

file_path = './Elastic_API/' + organization_id + '_' + str(report_month) + '_' + str(report_year) + '_Report_Data.csv'


# Connect to the elastic instance.
client = Elasticsearch(
    "https://ccdralescn01.rocusnetworks.local:9200",
    verify_certs=False,
    api_key=("hjaqT34BIH6T_vw3S4tj", "ixuZn8myQfCjJlEIciVB3g"),
    timeout=60,
)

# creating the body of the firewall request to only pull url_filtering events.
firewall_query = {
	"query": {
	"bool": {
		"must": 
        [],
			'filter': [
				{'range': {'@timestamp': {'gte': '2022-1-02T05:00:00.000Z', 'lte': '2022-02-01T05:00:00.000Z', "format": "strict_date_optional_time"}}},
                {'match_phrase': {"organization.id": str(organization_id)}},
                {'match_phrase': {'event.action': 'url_filtering'}},
                {'match_phrase': {'observer.type': 'firewall'}},
				]
				}
			}
		}

# creating the cylance request body so that all api hits or narrowed to CylancePROTECT events.
cylance_query = {
    "query": {
        "bool": {
            "must": [],
                "filter": [
                    {'range': {'@timestamp': {'gte': str(report_year) + '-' + str(report_month) + '-02T05:00:00.000Z', 'lte': str(currentYear) + '-' + str(currentMonth) + '-01T05:00:00.000Z', "format": "strict_date_optional_time"}}},
                    {'match_phrase': {"organization.id": str(organization_id)}},
                    {'match_phrase': {'event.module': 'CylancePROTECT'}},
                ]
        }
    }
}

# creating the mimecast request body so that all api hits are narrowed to CylancePROTECT events.
mimecast_query = {
    "query": {
        "bool": {
            "must": [],
                "filter": [
				    {'range': {'@timestamp': {'gte': str(report_year) + '-' + str(report_month) + '-02T05:00:00.000Z', 'lte': str(currentYear) + '-' + str(currentMonth) + '-01T05:00:00.000Z', "format": "strict_date_optional_time"}}},
                    {'match_phrase': {"organization.id": str(organization_id)}},
                    {'match_phrase': {'event.module': 'mimecast'}},
                ]
        }
    }
}

# resp = client.search(index='haven*', body=mimecast_query, size=10000)
# count = resp['hits']['total']['value']
# # print(count)
# for hit in resp['hits']['hits']:
#     print(hit['_source']['mimecast']['sender']['domain'])

# url filtering function. Creates a spreadsheet with all the url filtering information on it.
def url_filtering(firewall):
    resp = client.search(index='haven*', body=firewall, size=10000)

    for hit in resp['hits']['hits']:
        # making the file name automated to match the organization id that it is being run for.
        organization = hit['_source']['organization']['id']
        # creating and opening the file for this definition.
        with open('./Elastic_API/' + organization + '_Allowed_URLs.csv', 'w', newline='') as a, open('./Elastic_API/' + organization + '_Blocked_URLs.csv', 'w', newline='') as b,  open('./Elastic_API/' + organization + '_URL_totals.csv', 'w', newline='') as d:
            allowed_alert_list = {}
            allowed_columns = ['User Name', 'Event Outcome', 'URL', 'Source IP Address', 'Destination IP Address', 'Event Type']
            allowed_writer = csv.DictWriter(a, fieldnames=allowed_columns)
            allowed_writer.writeheader()

            blocked_alert_list = {}
            blocked_columns = ['User Name', 'Event Outcome', 'URL', 'Source IP Address', 'Destination IP Address', 'Event Type']
            blocked_writer = csv.DictWriter(b, fieldnames=blocked_columns)
            blocked_writer.writeheader()
            
            count_list = {}
            count_columns = ['URL Total', 'Allowed URLs', 'Blocked URLs', 'Total Unique Users (Allowed URLs', 'Total Unique Users (Blocked URLs']
            count_writer = csv.DictWriter(d, fieldnames=count_columns)
            count_writer.writeheader()

            count = resp['hits']['total']['value']
            for hit in resp['hits']['hits']:
                event_type = hit['_source']['event']['type']
                
                if event_type != ['allowed']:
                    user_name = {'User Name': hit['_source']['client']['user']['name']}
                    event_outcome = {'Event Outcome': hit['_source']['event']['outcome']}
                    url_original = {'URL': hit['_source']['url']['original']}
                    destination_ip = {'Destination IP Address': hit['_source']['destination']['ip']}
                    source_ip = {'Source IP Address': hit['_source']['source']['ip']}
                    allowed_blocked = {'Event Type': hit['_source']['event']['type']}

                    blocked_alert_list.update(user_name)
                    blocked_alert_list.update(event_outcome)
                    blocked_alert_list.update(url_original)
                    blocked_alert_list.update(source_ip)
                    blocked_alert_list.update(destination_ip)
                    blocked_update(allowed_blocked)
                    blocked_writer.writerow(blocked_alert_list)

            for hit in resp['hits']['hits']:
                event_type = hit['_source']['event']['type']
                
                if event_type == ['allowed']:
                    user_name = {'User Name': hit['_source']['client']['user']['name']}
                    event_outcome = {'Event Outcome': hit['_source']['event']['outcome']}
                    url_original = {'URL': hit['_source']['url']['original']}
                    destination_ip = {'Destination IP Address': hit['_source']['destination']['ip']}
                    source_ip = {'Source IP Address': hit['_source']['source']['ip']}
                    allowed_blocked = {'Event Type': hit['_source']['event']['type']}

                    allowed_alert_list.update(user_name)
                    allowed_alert_list.update(event_outcome)
                    allowed_alert_list.update(url_original)
                    allowed_alert_list.update(source_ip)
                    allowed_alert_list.update(destination_ip)
                    allowed_alert_list.update(allowed_blocked)
                    allowed_writer.writerow(allowed_alert_list)
            blocked_url = 0
            allowed_url = 0
            blocked_user = []
            allowed_user = []

            for hit in resp['hits']['hits']:
                event_type = hit['_source']['event']['type']
                
                if event_type == ['allowed']:
                    allowed_url = allowed_url + 1

                if event_type == ['allowed']:
                    for observer in  [hit['_source']['client']['user']['name']]:
                        # print(observer)
                        if observer not in allowed_user:
                            allowed_user.append(observer)

                if event_type != ['allowed']:
                    blocked_url = blocked_url + 1

                if event_type != ['allowed']:
                    for observer in  [hit['_source']['client']['user']['name']]:
                        # print(observer)
                        if observer not in blocked_user:
                            blocked_user.append(observer)

            # print(allowed_user)
            total_url = {'URL Total': count}
            blocked = {'Blocked URLs': blocked_url}
            allowed = {'Allowed URLs': allowed_url}
            allowed_users = {'Total Unique Users (Allowed URLs': len(allowed_user)}
            blocked_users = {'Total Unique Users (Blocked URLs': len(blocked_user)}
            count_list.update(total_url)
            count_list.update(allowed)
            count_list.update(blocked)
            count_list.update(allowed_users)
            count_list.update(blocked_users)
            count_writer.writerow(count_list)
        a.close()
        b.close()
        d.close()
        # pandas is used to group lines that are equal into one line and count them, it will delete all but one line and put a count of the records as a final column.
        allowed_file = pd.read_csv('./Elastic_API/' + organization + '_Allowed_URLs.csv')
        update_with_count = allowed_file.groupby(allowed_file.columns.tolist()).size().reset_index().rename(columns={0: 'Count'})
        update_with_count.sort_values(by=['Count'], ascending=False).to_csv('./Elastic_API/' + organization + '_Allowed_URLs.csv')

        blocked_file = pd.read_csv('./Elastic_API/' + organization + '_Blocked_URLs.csv')
        update_with_count = blocked_file.groupby(blocked_file.columns.tolist()).size().reset_index().rename(columns={0: 'Count'})
        update_with_count.sort_values(by=['Count'], ascending=False).to_csv('./Elastic_API/' + organization + '_Blocked_URLs.csv')

    return

# Cylance function for threats.
def cylance_threats(cylance):
    resp = client.search(index='haven*', body=cylance, size=10000)
    for hit in resp['hits']['hits']:
        # making the file name automated to match the organization id that it is being run for.
        organization = hit['_source']['organization']['id']
        # creating and opening the file for this definition.
        with open('./Elastic_API/' + organization + '_Quarantined_Threats.csv', 'w', newline='') as q, open('./Elastic_API/' + organization + '_Allowed_Threats.csv', 'w', newline='') as a:
            quarantined_list = {}
            allowed_list = {}
            columns = ['device_name', 'event_type', 'event_action', 'file_path', 'file_name']
            quarantined_writer = csv.DictWriter(q, fieldnames=columns)
            quarantined_writer.writeheader()

            allowed_writer = csv.DictWriter(a, fieldnames=columns)
            allowed_writer.writeheader()

            for hit in resp['hits']['hits']:
                event_type = hit['_source']['cylance']['event']['type']
                if event_type == 'Threat':
                    if 'Abnormal' in hit['_source']['event']['action'] or 'Unsafe' in hit['_source']['event']['action'] or 'Waived' in hit['_source']['event']['action']:
                        device_name = {'device_name': hit['_source']['observer']['name']}
                        event = {'event_type': event_type}
                        event_action = {'event_action': hit['_source']['event']['action']}
                        file_path = {'file_path': hit['_source']['file']['path']}
                        file_name = {'file_name': hit['_source']['file']['name']}

                        allowed_list.update(device_name)
                        allowed_list.update(event)
                        allowed_list.update(event_action)
                        allowed_list.update(file_path)
                        allowed_list.update(file_name)

                        allowed_writer.writerow(allowed_list)

            for hit in resp['hits']['hits']:
                event_type = hit['_source']['cylance']['event']['type']
                if event_type == 'Threat':
                    if 'Quarantined' in hit['_source']['event']['action'] or 'Cleared' in hit['_source']['event']['action']:
                        device_name = {'device_name': hit['_source']['observer']['name']}
                        event = {'event_type': event_type}
                        event_action = {'event_action': hit['_source']['event']['action']}
                        file_path = {'file_path': hit['_source']['file']['path']}
                        file_name = {'file_name': hit['_source']['file']['name']}

                        quarantined_list.update(device_name)
                        quarantined_list.update(event)
                        quarantined_list.update(event_action)
                        quarantined_list.update(file_path)
                        quarantined_list.update(file_name)

                        quarantined_writer.writerow(quarantined_list)
            q.close()
            a.close()
            # pandas is used to group lines that are equal into one line and count them, it will delete all but one line and put a count of the records as a final column.
            quarantined_file = pd.read_csv('./Elastic_API/' + organization + '_Quarantined_Threats.csv')
            update_with_count = quarantined_file.groupby(quarantined_file.columns.tolist()).size().reset_index().rename(columns={0: 'count'})
            update_with_count.sort_values(by=['count'], ascending=False).to_csv('./Elastic_API/' + organization + '_Quarantined_Threats.csv')

            allowed_file = pd.read_csv('./Elastic_API/' + organization + '_Allowed_Threats.csv')
            update_with_count = allowed_file.groupby(allowed_file.columns.tolist()).size().reset_index().rename(columns={0: 'count'})
            update_with_count.sort_values(by=['count'], ascending=False).to_csv('./Elastic_API/' + organization + '_Allowed_Threats.csv')    

    return

# pulls the cylance exploit attempts for the client and outputs to a csv.
def cylance_exploits(cylance):
    resp = client.search(index='haven*', body=cylance, size=10000)
    for hit in resp['hits']['hits']:
        # making the file name automated to match the organization id that it is being run for.
        organization = hit['_source']['organization']['id']
        # creating and opening the file for this definition.
        with open('./Elastic_API/' + organization + '_Cylance_Exploits.csv', 'w', newline='') as f:
            alert_list = {}
            columns = ['device_name', 'event_type', 'process_name', 'violation_type', 'event_action']
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            for hit in resp['hits']['hits']:
                event_type = hit['_source']['cylance']['event']['type']
                if event_type == 'ExploitAttempt':
                    device_name = {'device_name': hit['_source']['observer']['name']}
                    event = {'event_type': hit['_source']['cylance']['event']['type']}
                    process_name = {'process_name': hit['_source']['process']['name']}
                    violation_type =  {'violation_type': hit['_source']['cylance']['violation_type']}
                    event_action = {'event_action': hit['_source']['event']['action']}

                    alert_list.update(device_name)
                    alert_list.update(event)
                    alert_list.update(process_name)
                    alert_list.update(violation_type)
                    alert_list.update(event_action)

                    writer.writerow(alert_list)
        f.close()
        # pandas is used to group lines that are equal into one line and count them, it will delete all but one line and put a count of the records as a final column.
        read_file = pd.read_csv('./Elastic_API/' + organization + '_Cylance_Exploits.csv')
        update_with_count = read_file.groupby(read_file.columns.tolist()).size().reset_index().rename(columns={0: 'count'})
        update_with_count.sort_values(by=['count'], ascending=False).to_csv('./Elastic_API/' + organization + '_Cylance_Exploits.csv')
        return

# pulls the cylance script control events and outputs to a seperate csv.
def cylance_scripts(cylance):
    resp = client.search(index='haven*', body=cylance, size=10000)
    for hit in resp['hits']['hits']:
        # making the file name automated to match the organization id that it is being run for.
        organization = hit['_source']['organization']['id']
        # creating and opening the file for this definition.
        with open('./Elastic_API/' + organization + '_Cylance_Scripts.csv', 'w', newline='') as f:
            alert_list = {}
            columns = ['device_name', 'file_path', 'file_hash', 'type_of_script', 'event_action']
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            for hit in resp['hits']['hits']:
                event_type = hit['_source']['cylance']['event']['type']
                if event_type == 'ScriptControl':
                    device_name = {'device_name': hit['_source']['observer']['name']}
                    file_path = {'file_path': hit['_source']['file']['path']}
                    file_hash = {'file_hash': hit['_source']['file']['hash']['sha256']}
                    type_of_script = {'type_of_script': hit['_source']['cylance']['interpreter']}
                    event_action = {'event_action': hit['_source']['cylance']['event']['name']}

                    alert_list.update(device_name)
                    alert_list.update(file_path)
                    alert_list.update(file_hash)
                    alert_list.update(type_of_script)
                    alert_list.update(event_action)

                    writer.writerow(alert_list)
        f.close()
        # pandas is used to group lines that are equal into one line and count them, it will delete all but one line and put a count of the records as a final column.
        read_file = pd.read_csv('./Elastic_API/' + organization + '_Cylance_Scripts.csv')
        update_with_count = read_file.groupby(read_file.columns.tolist()).size().reset_index().rename(columns={0: 'count'})
        update_with_count.sort_values(by=['count'], ascending=False).to_csv('./Elastic_API/' + organization + '_Cylance_Scripts.csv')
        return

# pulls the cylance device control events and outputs to a seperate csv.
def cylance_deviceControl(cylance):
    resp = client.search(index='haven*', body=cylance, size=10000)
    for hit in resp['hits']['hits']:
        # making the file name automated to match the organization id that it is being run for.
        organization = hit['_source']['organization']['id']
        # creating and opening the file for this definition.
        with open('./Elastic_API/' + organization + '_Cylance_Device_Control.csv', 'w', newline='') as f:
            alert_list = {}
            columns = ['device_name', 'usb_device_name']
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            for hit in resp['hits']['hits']:
                event_type = hit['_source']['cylance']['event']['type']
                if event_type == 'DeviceControl':
                    device_name = {'device_name': hit['_source']['observer']['name']}
                    usb_device_name = {'usb_device_name': hit['_source']['cylance']['device']['name']}

                    alert_list.update(device_name)
                    alert_list.update(usb_device_name)

                    writer.writerow(alert_list)
        f.close()
        # pandas is used to group lines that are equal into one line and count them, it will delete all but one line and put a count of the records as a final column.
        read_file = pd.read_csv('./Elastic_API/' + organization + '_Cylance_Device_Control.csv')
        update_with_count = read_file.groupby(read_file.columns.tolist()).size().reset_index().rename(columns={0: 'count'})
        update_with_count.sort_values(by=['count'], ascending=False).to_csv('./Elastic_API/' + organization + '_Cylance_Device_Control.csv')
        return

# outputs to a csv, the total of each of the cylance events types.
def cylance_totals(cylance):
    resp = client.search(index='haven*', body=cylance, size=10000)
    for hit in resp['hits']['hits']:
        # making the file name automated to match the organization id that it is being run for.
        organization = hit['_source']['organization']['id']
        # creating and opening the file for this definition.
    with open('./Elastic_API/' + organization + '_Cylance_totals.csv', 'w', newline='') as f:
        alert_list = {}
        columns = ['Total Events', 'Total Devices', 'threats', 'exploit_attempt', 'script_control', 'device_control', 'quarantined', 'cleared', 'Unique Device Count (Threats Quarantined)', 'Unique Device Count (Threats Allowed)', 'Unique Device Count (Device Contorl)', 'Unique Device Count (ScriptControl)', 'Unique Device Count (Exploit Control)']
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        cylancePROTECT = 0
        device_count = []
        deviceControl_count = 0
        exploitAttempt_count = 0
        scriptControl_count = 0
        quarantined_count = 0
        cleared_count = 0
        unsafe_count = 0
        abnormal_count = 0
        waived_count = 0
        deviceControl_deviceName = []
        scriptControl_deviceName = []
        exploitControl_deviceName = []
        threatsQuarantined_deviceName = []
        threatsAllowed_deviceName = []
        hreatsAllowed_deviceName = []

        for hit in resp['hits']['hits']:
            if 'Device' != hit['_source']['cylance']['event']['type']:
                if 'ThreatClassification' != hit['_source']['cylance']['event']['type']:
                    if 'AuditLog' != hit['_source']['cylance']['event']['type']:
                        cylancePROTECT = cylancePROTECT + 1

        for hit in resp['hits']['hits']:
            try:
                for observer in hit['_source']['observer']['name']:
                    if observer not in device_count:
                        device_count.append(observer)
            except KeyError:
                continue


        for hit in resp['hits']['hits']:
            event_type = hit['_source']['cylance']['event']['type']
            # event_action = hit['_source']['event']['action']
            if event_type == 'DeviceControl':
                deviceControl_count = deviceControl_count + 1
            
            if event_type == 'DeviceControl':
                for observer in hit['_source']['observer']['name']:
                    if observer not in deviceControl_deviceName:
                        deviceControl_deviceName.append(observer)

        for hit in resp['hits']['hits']:
            event_type = hit['_source']['cylance']['event']['type']
            if event_type == 'ScriptControl':
                scriptControl_count = scriptControl_count + 1

            if event_type == 'ScriptControl':
                for observer in hit['_source']['observer']['name']:
                    if observer not in scriptControl_deviceName:
                        scriptControl_deviceName.append(observer)


        for hit in resp['hits']['hits']:
            event_type = hit['_source']['cylance']['event']['type']
            if event_type == 'ExploitAttempt':
                exploitAttempt_count = exploitAttempt_count +1

            if event_type == 'ExploitAttempt':
                for observer in hit['_source']['observer']['name']:
                    if observer not in exploitControl_deviceName:
                        exploitControl_deviceName.append(observer)

        for hit in resp['hits']['hits']:
            event_type = hit['_source']['cylance']['event']['type']          
            if event_type == 'Threat':
        
                event_action = hit['_source']['event']['action']
                if event_action == 'Quarantine' or 'Cleared':
                    quarantined_count = quarantined_count + 1

                # if event_action == 'Cleared':
                #     cleared_count = cleared_count + 1

                if event_action == 'Quarantine' or 'Cleared':
                    for observer in hit['_source']['observer']['name']:
                        if observer not in threatsQuarantined_deviceName:
                            threatsQuarantined_deviceName.append(observer)

                if event_action == 'Unsafe':
                    unsafe_count = unsafe_count + 1

                if event_action == 'Unsafe':
                    for observer in hit['_source']['observer']['name']:
                        if observer not in threatsAllowed_deviceName:
                            threatsAllowed_deviceName.append(observer)

                if event_action == 'Abnormal':
                    abnormal_count = abnormal_count + 1

                if event_action == 'Abnormal':
                    for observer in hit['_source']['observer']['name']:
                        if observer not in threatsAllowed_deviceName:
                            threatsAllowed_deviceName.append(observer)

                if event_action == 'Waived':
                    waived_count == waived_count + 1

                if event_action == 'Abnormal':
                    for observer in hit['_source']['observer']['name']:
                        if observer not in threatsAllowed_deviceName:
                            threatsAllowed_deviceName.append(observer)
                
        total_events = {'Total Events': cylancePROTECT}
        total_devices = {'Total Devices': len(device_count)}
        deviceControl = {'device_control': deviceControl_count}
        exploitAttempt = {'exploit_attempt': exploitAttempt_count}
        scriptControl = {'script_control': scriptControl_count}
        threats = {'threats': quarantined_count + cleared_count + cleared_count + abnormal_count + waived_count}
        quarantined = {'quarantined': quarantined_count + cleared_count}
        cleared = {'cleared': cleared_count + abnormal_count + waived_count}
        uniqueDevice_ThreatsQuarantined = {'Unique Device Count (Threats Quarantined)': len(threatsQuarantined_deviceName)}
        uniqueDevice_ThreatsAllowed = {'Unique Device Count (Threats Allowed)': len(threatsAllowed_deviceName)}
        uniqueDevice_DeviceControl = {'Unique Device Count (Device Contorl)': len(deviceControl_deviceName)}
        uniqueDevice_ScriptControl = {'Unique Device Count (ScriptControl)': len(scriptControl_deviceName)}
        uniqueDevice_ExploitControl = {'Unique Device Count (Exploit Control)': len(exploitControl_deviceName)}

        alert_list.update(total_events)
        alert_list.update(total_devices)
        alert_list.update(threats)
        alert_list.update(exploitAttempt)
        alert_list.update(scriptControl)
        alert_list.update(deviceControl)
        alert_list.update(quarantined)
        alert_list.update(cleared)
        alert_list.update(uniqueDevice_ThreatsQuarantined)
        alert_list.update(uniqueDevice_ThreatsAllowed)
        alert_list.update(uniqueDevice_DeviceControl)
        alert_list.update(uniqueDevice_ScriptControl)
        alert_list.update(uniqueDevice_ExploitControl)
        writer.writerow(alert_list)
    f.close()
    return

def mimecast(mimecast):
    resp = client.search(index='haven*', body=mimecast, size=10000)
    for hit in resp['hits']['hits']:
        # making the file name automated to match the organization id that it is being run for.
        organization = hit['_source']['organization.id']
        # creating and opening the file for this definition.
        with open('./Elastic_API/' + organization + '_Mimecast.csv', 'w', newline='') as f:
            alert_list = {}
            columns = ['source_email', 'sender_domain', 'header_from', 'destination_email', 'subject', 'network_direction']
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            for hit in resp['hits']['hits']:
                if 'receipt' in hit['_source']['mimecast']['event_type']:
                    if hit['_source']['network']['direction'] == 'Inbound':
                        if hit['_source']['event']['action'] == 'Acc':
                            if 'zendesk.com' not in hit['_source']['mimecast']['sender']['domain'] and 'amazonses.com' not in hit['_source']['mimecast']['sender']['domain'] and 'atlassian.net' not in hit['_source']['mimecast']['sender']['domain']:
                                direction = {'network_direction': hit['_source']['network']['direction']}
                                domain = {'sender_domain': hit['_source']['mimecast']['sender']['domain']}
                                destination_email = {'destination_email': hit['_source']['destination']['user']['email']}
                                
                                # this try/except looks for source email and if the field is empty or undefined, fills the space in with '  -  '.
                                try:
                                    source_email = {'source_email': hit['_source']['source']['user']['email']}
                                    alert_list.update(source_email)

                                except KeyError:
                                    no_source_email = {'source_email': '  -  '}
                                    alert_list.update(no_source_email)                               
                                    
                                # this try/except looks for header_from and if the field is empty or undefined, fills the space in with '  -  '.
                                try:
                                    header_from = {'header_from': hit['_source']['mimecsast']['header_from']}
                                    alert_list.update(header_from)
                                        
                                except KeyError:
                                    no_header_from = {'header_from': '  -  '}
                                    alert_list.update(no_header_from)
                                    
                                # this try/except looks for the email's subject line and if the field is empty or undefined, fills the space in with '  -  '.
                                try:
                                    subject = {'subject': hit['_source']['mimecast']['subject']}
                                    alert_list.update(subject)
                                except KeyError:
                                    no_subject = {'subject': '  -  '}
                                    alert_list.update(no_subject)

                                # we now write the dictionary from all the informaiton gatheered to a csv.
                                alert_list.update(direction)
                                alert_list.update(domain)
                                alert_list.update(destination_email)
                                
                                writer.writerow(alert_list)
                            
            f.close()
            # pandas is used to group lines that are equal into one line and count them, it will delete all but one line and put a count of the records as a final column.
            read_file = pd.read_csv('./Elastic_API/' + organization + '_Mimecast.csv')
            update_with_count = read_file.groupby(read_file.columns.tolist()).size().reset_index().rename(columns={0: 'count'})
            update_with_count.sort_values(by=['count'], ascending=False).to_csv('./Elastic_API/' + organization + '_Mimecast.csv')

            return

def fill_sheet():
    input_file = pd.read_csv('./Elastic_API/Report_Data_Gathering.csv')
    with open('./Elastic_API/' + organization_id + '_' + str(report_month) + '_' + str(report_year) + '_Report_Data.csv', 'w') as f:

        firewall_Totals = pd.read_csv('./Elastic_API/' + organization_id + '_URL_totals.csv')
        allowed_URLS = pd.read_csv('./Elastic_API/' + organization_id + '_Allowed_URLs.csv')
        blocked_URLS = pd.read_csv('./Elastic_API/' + organization_id + '_Blocked_URLs.csv')
        cylanceTotals = pd.read_csv('./Elastic_API/' + organization_id + '_Cylance_totals.csv')
        cylanceDevices = pd.read_csv('./Elastic_API/' + organization_id + '_Cylance_Device_Control.csv')
        cylanceScripts = pd.read_csv('./Elastic_API/' + organization_id + '_Cylance_Scripts.csv')
        quarantinedThreats = pd.read_csv('./Elastic_API/' + organization_id + '_Quarantined_Threats.csv')
        allowedThreats = pd.read_csv('./Elastic_API/' + organization_id + '_Allowed_Threats.csv')

        try:
            # Filling in cylance totals
            input_file.iat[1,2] = str(cylanceTotals.iloc[0,0])
            input_file.iat[3,2] = str(cylanceTotals.iloc[0,1])
            input_file.iat[4,2] = str(cylanceTotals.iloc[0,5])
            input_file.iat[5,2] = str(cylanceTotals.iloc[0,10])
            input_file.iat[6,2] = str(cylanceTotals.iloc[0,6])
            input_file.iat[7,2] = str(cylanceTotals.iloc[0,8])
            input_file.iat[8,2] = str(cylanceTotals.iloc[0,2])
            input_file.iat[9,2] = str(cylanceTotals.iloc[0,4])
            input_file.iat[10,2] = str(cylanceTotals.iloc[0,11])
            input_file.iat[11,2] = str(cylanceTotals.iloc[0,3])
            input_file.iat[12,2] = str(cylanceTotals.iloc[0,12])

        except IndexError:
            input_file.iat[1,2] = 'N/A'
            input_file.iat[3,2] = 'N/A'
            input_file.iat[4,2] = 'N/A'
            input_file.iat[5,2] = 'N/A'
            input_file.iat[6,2] = 'N/A'
            input_file.iat[7,2] = 'N/A'
            input_file.iat[8,2] = 'N/A'
            input_file.iat[9,2] = 'N/A'
            input_file.iat[10,2] = 'N/A'
            input_file.iat[11,2] = 'N/A'
            input_file.iat[12,2] = 'N/A'

            # Filling in totals for URLs

        try:
            input_file.iat[2,2] = str(firewall_Totals.iloc[0,0])
            input_file.iat[53,2] = str(firewall_Totals.iloc[0,0])
            # wks.update('C54', str(firewall_Totals.iloc[0,2])) count url's assocated with user per block
            input_file.iat[55,2] = str(firewall_Totals.iloc[0,1])
            input_file.iat[56,2] = str(firewall_Totals.iloc[0,4])
            input_file.iat[57,2] = str(firewall_Totals.iloc[0,2])

        except IndexError:
            input_file.iat[2,2] = 'N/A'
            input_file.iat[53,2] = 'N/A'
            # wks.update('C54', str(firewall_Totals.iloc[0,2])) count url's assocated with user per block
            input_file.iat[55,2] = 'N/A'
            input_file.iat[56,2] = 'N/A'
            input_file.iat[57,2] = 'N/A'

        # Table 2 and Table 4
        try:
            # Table 2
            input_file.iat[14,2] = str(cylanceDevices.iloc[0,1])
            input_file.iat[14,4] = str(cylanceDevices.iloc[0,3])
            input_file.iat[15,2] = str(cylanceDevices.iloc[1,1])
            input_file.iat[15,4] = str(cylanceDevices.iloc[1,3])
            input_file.iat[16,2] = str(cylanceDevices.iloc[2,1])
            input_file.iat[16,4] = str(cylanceDevices.iloc[2,3])
            input_file.iat[17,2] = str(cylanceDevices.iloc[3,1])
            input_file.iat[17,4] = str(cylanceDevices.iloc[3,3])
            input_file.iat[18,2] = str(cylanceDevices.iloc[4,1])
            input_file.iat[18,4] = str(cylanceDevices.iloc[4,3])

            # Table 4
            input_file.iat[20,2] = str(cylanceDevices.iloc[0,1])
            input_file.iat[20,4] = str(cylanceDevices.iloc[0,2])
            input_file.iat[20,6] = str(cylanceDevices.iloc[0,3])
            input_file.iat[21,2] = str(cylanceDevices.iloc[1,1])
            input_file.iat[21,4] = str(cylanceDevices.iloc[1,2])
            input_file.iat[21,6] = str(cylanceDevices.iloc[1,3])
            input_file.iat[22,2] = str(cylanceDevices.iloc[2,1])
            input_file.iat[22,4] = str(cylanceDevices.iloc[2,2])
            input_file.iat[22,6] = str(cylanceDevices.iloc[2,3])
            input_file.iat[23,2] = str(cylanceDevices.iloc[3,1])
            input_file.iat[23,4] = str(cylanceDevices.iloc[3,2])
            input_file.iat[23,6] = str(cylanceDevices.iloc[3,3])
            input_file.iat[24,2] = str(cylanceDevices.iloc[4,1])
            input_file.iat[24,4] = str(cylanceDevices.iloc[4,2])
            input_file.iat[24,6] = str(cylanceDevices.iloc[4,3])

        except IndexError:
            # Table 2
            input_file.iat[14,2] = 'N/A'
            input_file.iat[14,4] = 'N/A'
            input_file.iat[15,2] = 'N/A'
            input_file.iat[15,4] = 'N/A'
            input_file.iat[16,2] = 'N/A'
            input_file.iat[16,4] = 'N/A'
            input_file.iat[17,2] = 'N/A'
            input_file.iat[17,4] = 'N/A'
            input_file.iat[18,2] = 'N/A'
            input_file.iat[18,4] = 'N/A'

            # Table 4
            input_file.iat[20,2] = 'N/A'
            input_file.iat[20,4] = 'N/A'
            input_file.iat[20,6] = 'N/A'
            input_file.iat[21,2] = 'N/A'
            input_file.iat[21,4] = 'N/A'
            input_file.iat[21,6] = 'N/A'
            input_file.iat[22,2] = 'N/A'
            input_file.iat[22,4] = 'N/A'
            input_file.iat[22,6] = 'N/A'
            input_file.iat[23,2] = 'N/A'
            input_file.iat[23,4] = 'N/A'
            input_file.iat[23,6] = 'N/A'
            input_file.iat[24,2] = 'N/A'
            input_file.iat[24,4] = 'N/A'
            input_file.iat[24,6] = 'N/A'
            

        # Filling the tables for Execution Control
        try:
            # Table 5
            input_file.iat[26,2] = str(quarantinedThreats.iloc[0,1])
            input_file.iat[26,4] = str(quarantinedThreats.iloc[0,4])
            input_file.iat[26,6] = str(quarantinedThreats.iloc[0,5])
            input_file.iat[26,8] = str(quarantinedThreats.iloc[0,6])
            input_file.iat[27,2] = str(quarantinedThreats.iloc[1,1])
            input_file.iat[27,4] = str(quarantinedThreats.iloc[1,4])
            input_file.iat[27,6] = str(quarantinedThreats.iloc[1,5])
            input_file.iat[27,8] = str(quarantinedThreats.iloc[1,6])
            input_file.iat[28,2] = str(quarantinedThreats.iloc[2,1])
            input_file.iat[28,4] = str(quarantinedThreats.iloc[2,4])
            input_file.iat[28,6] = str(quarantinedThreats.iloc[2,5])
            input_file.iat[28,8] = str(quarantinedThreats.iloc[2,6])
            input_file.iat[29,2] = str(quarantinedThreats.iloc[3,1])
            input_file.iat[29,4] = str(quarantinedThreats.iloc[3,4])
            input_file.iat[29,6] = str(quarantinedThreats.iloc[3,5])
            input_file.iat[29,8] = str(quarantinedThreats.iloc[3,6])
            input_file.iat[30,2] = str(quarantinedThreats.iloc[4,1])
            input_file.iat[30,4] = str(quarantinedThreats.iloc[4,4])
            input_file.iat[30,6] = str(quarantinedThreats.iloc[4,5])
            input_file.iat[30,8] = str(quarantinedThreats.iloc[4,6])

            # Table 6
            input_file.iat[32,2] = str(allowedThreats.iloc[0,1])
            input_file.iat[32,4] = str(allowedThreats.iloc[0,4])
            input_file.iat[32,6] = str(allowedThreats.iloc[0,5])
            input_file.iat[32,8] = str(allowedThreats.iloc[0,6])
            input_file.iat[33,2] = str(allowedThreats.iloc[1,1])
            input_file.iat[33,4] = str(allowedThreats.iloc[1,4])
            input_file.iat[33,6] = str(allowedThreats.iloc[1,5])
            input_file.iat[33,8] = str(allowedThreats.iloc[1,6])
            input_file.iat[34,2] = str(allowedThreats.iloc[2,1])
            input_file.iat[34,4] = str(allowedThreats.iloc[2,4])
            input_file.iat[34,6] = str(allowedThreats.iloc[2,5])
            input_file.iat[34,8] = str(allowedThreats.iloc[2,6])
            input_file.iat[35,2] = str(allowedThreats.iloc[3,1])
            input_file.iat[35,4] = str(allowedThreats.iloc[3,4])
            input_file.iat[35,6] = str(allowedThreats.iloc[3,5])
            input_file.iat[35,8] = str(allowedThreats.iloc[3,6])
            input_file.iat[36,2] = str(allowedThreats.iloc[4,1])
            input_file.iat[36,4] = str(allowedThreats.iloc[4,4])
            input_file.iat[36,6] = str(allowedThreats.iloc[4,5])
            input_file.iat[36,8] = str(allowedThreats.iloc[4,6])

        except IndexError:
            input_file.iat[26,4] = 'N/A'
            input_file.iat[26,6] = 'N/A'
            input_file.iat[26,8] = 'N/A'
            input_file.iat[27,2] = 'N/A'
            input_file.iat[27,4] = 'N/A'
            input_file.iat[27,6] = 'N/A'
            input_file.iat[27,8] = 'N/A'
            input_file.iat[28,2] = 'N/A'
            input_file.iat[28,4] = 'N/A'
            input_file.iat[28,6] = 'N/A'
            input_file.iat[28,8] = 'N/A'
            input_file.iat[29,2] = 'N/A'
            input_file.iat[29,6] = 'N/A'
            input_file.iat[29,8] = 'N/A'
            input_file.iat[29,4] = 'N/A'
            input_file.iat[30,4] = 'N/A'
            input_file.iat[30,6] = 'N/A'
            input_file.iat[30,8] = 'N/A'
            input_file.iat[30,2] = 'N/A'

            # Table 6
            input_file.iat[32,2] = 'N/A'
            input_file.iat[32,4] = 'N/A'
            input_file.iat[32,6] = 'N/A'
            input_file.iat[32,8] = 'N/A'
            input_file.iat[33,2] = 'N/A'
            input_file.iat[33,4] = 'N/A'
            input_file.iat[33,6] = 'N/A'
            input_file.iat[33,8] = 'N/A'
            input_file.iat[34,2] = 'N/A'
            input_file.iat[34,4] = 'N/A'
            input_file.iat[34,6] = 'N/A'
            input_file.iat[34,8] = 'N/A'
            input_file.iat[35,2] = 'N/A'
            input_file.iat[35,4] = 'N/A'
            input_file.iat[35,6] = 'N/A'
            input_file.iat[35,8] = 'N/A'
            input_file.iat[36,2] = 'N/A'
            input_file.iat[36,4] = 'N/A'
            input_file.iat[36,6] = 'N/A'
            input_file.iat[36,8] = 'N/A'
        
        # Filling in Script Control Tables
        try:
            # Table 7
            input_file.iat[38,2] = str(cylanceScripts.iloc[0,1])
            input_file.iat[38,4] = str(cylanceScripts.iloc[0,2])
            input_file.iat[38,6] = str(cylanceScripts.iloc[0,4])
            input_file.iat[38,8] = str(cylanceScripts.iloc[0,6])
            input_file.iat[39,2] = str(cylanceScripts.iloc[1,1])
            input_file.iat[39,4] = str(cylanceScripts.iloc[1,2])
            input_file.iat[39,6] = str(cylanceScripts.iloc[1,4])
            input_file.iat[39,8] = str(cylanceScripts.iloc[1,6])
            input_file.iat[40,2] = str(cylanceScripts.iloc[2,1])
            input_file.iat[40,4] = str(cylanceScripts.iloc[2,2])
            input_file.iat[40,6] = str(cylanceScripts.iloc[2,4])
            input_file.iat[40,8] = str(cylanceScripts.iloc[2,6])
            input_file.iat[41,2] = str(cylanceScripts.iloc[3,1])
            input_file.iat[41,4] = str(cylanceScripts.iloc[3,2])
            input_file.iat[41,6] = str(cylanceScripts.iloc[3,4])
            input_file.iat[41,8] = str(cylanceScripts.iloc[3,6])
            input_file.iat[42,2] = str(cylanceScripts.iloc[4,1])
            input_file.iat[42,4] = str(cylanceScripts.iloc[4,2])
            input_file.iat[42,6] = str(cylanceScripts.iloc[4,4])
            input_file.iat[42,8] = str(cylanceScripts.iloc[4,6])

            # Table 8
            input_file.iat[44,2] = str(cylanceScripts.iloc[0,3])
            input_file.iat[44,4] = str(cylanceScripts.iloc[0,1])
            input_file.iat[44,6] = str(cylanceScripts.iloc[0,2])
            input_file.iat[44,8] = str(cylanceScripts.iloc[0,6])
            input_file.iat[45,2] = str(cylanceScripts.iloc[1,3])
            input_file.iat[45,4] = str(cylanceScripts.iloc[1,1])
            input_file.iat[45,6] = str(cylanceScripts.iloc[1,2])
            input_file.iat[45,8] = str(cylanceScripts.iloc[1,6])
            input_file.iat[46,2] = str(cylanceScripts.iloc[2,3])
            input_file.iat[46,4] = str(cylanceScripts.iloc[2,1])
            input_file.iat[46,6] = str(cylanceScripts.iloc[2,2])
            input_file.iat[46,8] = str(cylanceScripts.iloc[2,6])
            input_file.iat[47,2] = str(cylanceScripts.iloc[3,3])
            input_file.iat[47,4] = str(cylanceScripts.iloc[3,1])
            input_file.iat[47,6] = str(cylanceScripts.iloc[3,2])
            input_file.iat[47,8] = str(cylanceScripts.iloc[3,6])
            input_file.iat[48,2] = str(cylanceScripts.iloc[4,3])
            input_file.iat[48,4] = str(cylanceScripts.iloc[4,1])
            input_file.iat[48,6] = str(cylanceScripts.iloc[4,2])
            input_file.iat[48,8] = str(cylanceScripts.iloc[4,6])

        except IndexError:
            # Table 7
            input_file.iat[38,2] = 'N/A'
            input_file.iat[38,4] = 'N/A'
            input_file.iat[38,6] = 'N/A'
            input_file.iat[38,8] = 'N/A'
            input_file.iat[39,2] = 'N/A'
            input_file.iat[39,4] = 'N/A'
            input_file.iat[39,6] = 'N/A'
            input_file.iat[39,8] = 'N/A'
            input_file.iat[40,2] = 'N/A'
            input_file.iat[40,4] = 'N/A'
            input_file.iat[40,6] = 'N/A'
            input_file.iat[40,8] = 'N/A'
            input_file.iat[41,2] = 'N/A'
            input_file.iat[41,4] = 'N/A'
            input_file.iat[41,6] = 'N/A'
            input_file.iat[41,8] = 'N/A'
            input_file.iat[42,2] = 'N/A'
            input_file.iat[42,4] = 'N/A'
            input_file.iat[42,6] = 'N/A'
            input_file.iat[42,8] = 'N/A'

            # Table 8
            input_file.iat[44,2] = 'N/A'
            input_file.iat[44,4] = 'N/A'
            input_file.iat[44,6] = 'N/A'
            input_file.iat[44,8] = 'N/A'
            input_file.iat[45,2] = 'N/A'
            input_file.iat[45,4] = 'N/A'
            input_file.iat[45,6] = 'N/A'
            input_file.iat[45,8] = 'N/A'
            input_file.iat[46,2] = 'N/A'
            input_file.iat[46,4] = 'N/A'
            input_file.iat[46,6] = 'N/A'
            input_file.iat[46,8] = 'N/A'
            input_file.iat[47,2] = 'N/A'
            input_file.iat[47,4] = 'N/A'
            input_file.iat[47,6] = 'N/A'
            input_file.iat[47,8] = 'N/A'
            input_file.iat[48,2] = 'N/A'
            input_file.iat[48,4] = 'N/A'
            input_file.iat[48,6] = 'N/A'
            input_file.iat[48,8] = 'N/A'
        
        # Filling in the Allowed URL section of the sheet.           
        try:
            input_file.iat[59,2] = str(allowed_URLS.iloc[0,3])
            input_file.iat[59,4] = str(allowed_URLS.iloc[0,7])
            input_file.iat[60,2] = str(allowed_URLS.iloc[1,3])
            input_file.iat[60,4] = str(allowed_URLS.iloc[1,7])
            input_file.iat[61,2] = str(allowed_URLS.iloc[2,3])
            input_file.iat[61,4] = str(allowed_URLS.iloc[2,7])
            input_file.iat[62,2] = str(allowed_URLS.iloc[3,3])
            input_file.iat[62,4] = str(allowed_URLS.iloc[3,7])
            input_file.iat[63,2] = str(allowed_URLS.iloc[4,3])
            input_file.iat[63,4] = str(allowed_URLS.iloc[4,7])

        except IndexError:
            input_file.iat[59,2] = 'N/A'
            input_file.iat[59,4] = 'N/A'
            input_file.iat[60,2] = 'N/A'
            input_file.iat[60,4] = 'N/A'
            input_file.iat[61,2] = 'N/A'
            input_file.iat[61,4] = 'N/A'
            input_file.iat[62,2] = 'N/A'
            input_file.iat[62,4] = 'N/A'
            input_file.iat[63,2] = 'N/A'
            input_file.iat[63,4] = 'N/A'

            #filling in the blocked URL Section

        # Filling in the Blocked URL section of the sheet.
        try:
            input_file.iat[65,2] = str(blocked_URLS.iloc[0,3])
            input_file.iat[65,4] = str(blocked_URLS.iloc[0,7])
            input_file.iat[66,2] = str(blocked_URLS.iloc[1,3])
            input_file.iat[66,4] = str(blocked_URLS.iloc[1,7])
            input_file.iat[67,2] = str(blocked_URLS.iloc[2,3])
            input_file.iat[67,4] = str(blocked_URLS.iloc[2,7])
            input_file.iat[68,2] = str(blocked_URLS.iloc[3,3])
            input_file.iat[68,4] = str(blocked_URLS.iloc[3,7])
            input_file.iat[69,2] = str(blocked_URLS.iloc[4,3])
            input_file.iat[69,4] = str(blocked_URLS.iloc[4,7])

        except IndexError:
            input_file.iat[65,2] = 'N/A'
            input_file.iat[65,4] = 'N/A'
            input_file.iat[66,2] = 'N/A'
            input_file.iat[66,4] = 'N/A'
            input_file.iat[67,2] = 'N/A'
            input_file.iat[67,4] = 'N/A'
            input_file.iat[68,2] = 'N/A'
            input_file.iat[68,4] = 'N/A'
            input_file.iat[69,2] = 'N/A'
            input_file.iat[69,4] = 'N/A'

        input_file.to_csv(f)

def create_google_folder():
    credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
    service = build('drive', 'v3', credentials=credentials)
    file_metadata = {
    'name': organization_id + '_' + str(currentMonth) + '_' + str(currentYear),
    'mimeType': 'application/vnd.google-apps.folder',
    'parents': ['1CkOwPmUeb6VdiqZScCu45SP_QBXN1Z1w']
    }
    file = service.files().create(body=file_metadata, fields='id').execute()

    page_token = None
    response = service.files().list(q="mimeType='application/vnd.google-apps.folder'", spaces='drive', fields='nextPageToken, files(id, name)', pageToken=page_token).execute()
    for file in response.get('files', []):
        if file.get('name') == organization_id + '_' + str(currentMonth) + '_' + str(currentYear):
            file_id = file.get('id')
    return print(file_id), file_id

def export_csv_file(file_path: str, parents: list=None):
    file_name = file_path + organization_id + '_' + str(currentMonth) + '_' + str(currentYear) + '_Report_Data.csv'
    if not os.path.exists(file_path):
        print(f"{file_path} not found.")
        return
    try:
        file_metadata = {
            'name': os.path.basename(file_path).replace('.csv', ''),
            'mimetype': 'application/vnd.google-apps.spreadsheet',
            'parents': parents,
        }
        media = MediaFileUpload(filename=file_path, mimetype='text/csv')

        response = service.files().create(media_body=media, body=file_metadata).execute()
        print(response)
        return response
    except Exception as e:
        print(e)
        return

def upload_to_drive():
    credentials = ServiceAccountCredentials.from_json_keyfile_name('client_secret.json')
    service = build('drive', 'v3', credentials=credentials)
    page_token = None
    response = service.files().list(q="mimeType='application/vnd.google-apps.folder'", spaces='drive', fields='nextPageToken, files(id, name)', pageToken=page_token).execute()
    cwd = os.getcwd()
    file_name = file_path + organization_id + '_' + str(currentMonth) + '_' + str(currentYear) + '.csv'
    for file in response.get('files', []):
        if file.get('name') == organization_id + '_' + str(currentMonth) + '_' + str(currentYear):
            file_id = file.get('id')
            print(file.get('name'), file_id)
            export_csv_file(os.path.join(cwd, file_name), parents=[file_id])

if __name__ == "__main__":
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        executor.submit(url_filtering, firewall_query)
        executor.submit(cylance_threats, cylance_query)
        executor.submit(cylance_deviceControl, cylance_query)
        executor.submit(cylance_exploits, cylance_query)
        executor.submit(cylance_scripts, cylance_query)
        executor.submit(cylance_totals, cylance_query)
        executor.submit(mimecast, mimecast_query)
        executor.submit(fill_sheet, )
        # executor.submit(create_google_folder,)
        # executor.submit(upload_to_drive, )
        

