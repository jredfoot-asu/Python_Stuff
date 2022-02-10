from elasticsearch import Elasticsearch
import json
import csv
import pandas as pd
import os.path
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
organization_id = 'aaaam4'


# Connect to the elastic instance.
client = Elasticsearch(
    "https://lb-es.rocusnetworks.local:9200",
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
				{'range': {'@timestamp': {'gte': '2021-11-02T05:00:00.000Z', 'lte': '2021-12-01T05:00:00.000Z', "format": "strict_date_optional_time"}}},
                {'match_phrase': {"organization.id": 'aaaam4'}},
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
                    {'range': {'@timestamp': {'gte': '2021-11-02T05:00:00.000Z', 'lte': '2021-12-01T05:00:00.000Z', "format": "strict_date_optional_time"}}},
                    {'match_phrase': {"organization.id": 'aaaam4'}},
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
                    {'range': {'@timestamp': {'gte': '2021-11-01T05:00:00.000Z', 'lte': '2021-12-01T05:00:00.000Z', "format": "strict_date_optional_time"}}},
                    {'match_phrase': {"organization.id": 'aaaam4'}},
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

url_total = 0

# url filtering function. Creates a spreadsheet with all the url filtering information on it.
def url_filtering(firewall):
    resp = client.search(index='haven*', body=firewall, size=10000)

    for hit in resp['hits']['hits']:
        # making the file name automated to match the organization id that it is being run for.
        organization = hit['_source']['organization']['id']
        # creating and opening the file for this definition.
        with open('./Elastic_API/' + organization + '_URLs.csv', 'w', newline='') as f:
            alert_list = {}
            columns = ['User Name', 'Event Outcome', 'URL', 'Source IP Address', 'Destination IP Address']
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            count = resp['hits']['total']['value']
            for hit in resp['hits']['hits']:
                user_name = {'User Name': hit['_source']['client']['user']['name']}
                event_outcome = {'Event Outcome': hit['_source']['event']['outcome']}
                url_original = {'URL': hit['_source']['url']['original']}
                destination_ip = {'Destination IP Address': hit['_source']['destination']['ip']}
                source_ip = {'Source IP Address': hit['_source']['source']['ip']}

                alert_list.update(user_name)
                alert_list.update(event_outcome)
                alert_list.update(url_original)
                alert_list.update(source_ip)
                alert_list.update(destination_ip)
                writer.writerow(alert_list)
        f.close()
        # pandas is used to group lines that are equal into one line and count them, it will delete all but one line and put a count of the records as a final column.
        read_file = pd.read_csv('./Elastic_API/' + organization + '_URLs.csv')
        url_toal = len(read_file)
        update_with_count = read_file.groupby(read_file.columns.tolist()).size().reset_index().rename(columns={0: 'Count'})
        update_with_count.sort_values(by=['Count'], ascending=False).to_csv('./Elastic_API/' + organization + '_URLs.csv')
    return


# Cylance function for threats.
def cylance_threats(cylance):
    resp = client.search(index='haven*', body=cylance, size=10000)
    for hit in resp['hits']['hits']:
        # making the file name automated to match the organization id that it is being run for.
        organization = hit['_source']['organization']['id']
        # creating and opening the file for this definition.
        with open('./Elastic_API/' + organization + '_Cylance_Threats.csv', 'w', newline='') as f:
            alert_list = {}
            columns = ['device_name', 'event_type', 'event_action', 'file_path', 'file_name']
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            for hit in resp['hits']['hits']:
                event_type = hit['_source']['cylance']['event']['type']
                if event_type == 'Threat':
                    device_name = {'device_name': hit['_source']['observer']['name']}
                    event = {'event_type': event_type}
                    event_action = {'event_action': hit['_source']['event']['action']}
                    file_path = {'file_path': hit['_source']['file']['path']}
                    file_name = {'file_name': hit['_source']['file']['name']}

                    alert_list.update(device_name)
                    alert_list.update(event)
                    alert_list.update(event_action)
                    alert_list.update(file_path)
                    alert_list.update(file_name)

                    writer.writerow(alert_list)
            f.close()
            # pandas is used to group lines that are equal into one line and count them, it will delete all but one line and put a count of the records as a final column.
            read_file = pd.read_csv('./Elastic_API/' + organization + '_Cylance_Threats.csv')
            update_with_count = read_file.groupby(read_file.columns.tolist()).size().reset_index().rename(columns={0: 'count'})
            update_with_count.sort_values(by=['count'], ascending=False).to_csv('./Elastic_API/' + organization + '_Cylance_Threats.csv')
    
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


# deviceControl_count = 0
# exploitAttempt_count = 0
# scriptControl_count = 0
# threats_count = 0

# outputs to a csv, the total of each of the cylance events types.
def cylance_totals(cylance):
    resp = client.search(index='haven*', body=cylance, size=10000)
    for hit in resp['hits']['hits']:
        # making the file name automated to match the organization id that it is being run for.
        organization = hit['_source']['organization']['id']
        # creating and opening the file for this definition.
    with open('./Elastic_API/' + organization + '_Cylance_totals.csv', 'w', newline='') as f:
        alert_list = {}
        columns = ['threats', 'exploit_attempt', 'script_control', 'device_control', 'quarantined', 'cleared', 'Unique Device Count (Threats Quarantined)', 'Unique Device Count (Threats Allowed)', 'Unique Device Count (Device Contorl)', 'Unique Device Count (ScriptControl)', 'Unique Device Count (Exploit Control)']
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
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

        print(len(threatsQuarantined_deviceName), threatsAllowed_deviceName, len(deviceControl_deviceName), len(scriptControl_deviceName), len(exploitControl_deviceName))

                
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

def create_google_folder():
    credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
    service = build('drive', 'v3', credentials=credentials)
    file_metadata = {
    'name': organization_id + '_' + str(currentMonth) + '_' + str(currentYear),
    'mimeType': 'application/vnd.google-apps.folder',
    'parents': ['1CkOwPmUeb6VdiqZScCu45SP_QBXN1Z1w']
    }
    file = service.files().create(body=file_metadata, fields='id').execute()

def copy_sheet_template():
    credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
    service = build('drive', 'v3', credentials=credentials)
    page_token = None
    response = service.files().list(q="mimeType='application/vnd.google-apps.folder'", spaces='drive', fields='nextPageToken, files(id, name)', pageToken=page_token).execute()
    for file in response.get('files', []):
        if file.get('name') == organization_id + '_' + str(currentMonth) + '_' + str(currentYear):
            print ('Found file: %s (%s)' % (file.get('name'), file.get('id')))
            sa = gspread.service_account(filename='./Elastic_API/client_secret.json')
            sa.copy('1OgAs8jG-6bBqE3LoN4ojaCX0B1SyecrtAcRd4LeSliY', title=organization_id + '_' + str(currentMonth) + '_' + str(currentYear), copy_permissions=True, folder_id=file.get('id'))
            report = sa.open('aaaam4')
            wks = report.worksheet('Sheet1')
            # wks.update('C3', 'Fill-Out')


# url_filtering(firewall_query)
# cylance_threats(cylance_query)
# cylance_exploits(cylance_query)
# cylance_scripts(cylance_query)
# cylance_deviceControl(cylance_query)
cylance_totals(cylance_query)

# mimecast(mimecast_query)

# print(url_total)

# create_google_folder()
# copy_sheet_template()