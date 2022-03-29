from elasticsearch import Elasticsearch
import json
import csv
import pandas as pd
import os.path
import time
import threading
import concurrent.futures
from functools import partial
from oauth2client.service_account import ServiceAccountCredentials
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload
from datetime import datetime
import gspread
import requests


currentMonth = datetime.now().month
currentYear = datetime.now().year
organization_id = ['aaaao7', 'aaaak0', 'aaaam4', 'aaaar5', 'aaaai6', 'aaaak5', 'aaaal0']

report_month = 0
report_year = 0

if currentMonth == 1:
    report_month = 12
    report_year = currentYear -1
else:
    report_month = currentMonth - 1
    report_year = currentYear

report_start = str(report_year) +'-' + str(report_month) + '-01T05:00:00.000Z'
report_end = str(currentYear) + '-' + str(currentMonth) +'-01T05:00:00.000Z'

# file_path = './Elastic_API/' + organization_id + '_' + str(report_month) + '_' + str(report_year) + '_Report_Data.csv'


# Connect to the elastic instance.
client = Elasticsearch(
    "https://ccdralescn01.rocusnetworks.local:9200",
    verify_certs=False,
    # Todo: change api key information
    api_key=("PT6BHH8BIH6T_vw3lV4a", "0Mvhf1IASZm2WI_3Oi5Kwg"),
    timeout=600,
)

# url filtering function. Creates a spreadsheet with all the url filtering information on it.
def blocked_url_filtering(firewall, organization):
    resp = client.search(index='haven*', body=firewall, size=5)
    # Todo: change file path
    with open('./Elastic_API/' + organization + '_Blocked_URLs.csv', 'w', newline='') as b:

        blocked_alert_list = {}
        blocked_columns = ['User Name', 'URL', 'Source IP Address', 'Destination IP Address', 'Count']
        blocked_writer = csv.DictWriter(b, fieldnames=blocked_columns)
        blocked_writer.writeheader()
    
        for response in resp['aggregations']['top_users']['buckets']:    
            for url in response['top_urls']['buckets']:
                for sourceIP in url['source_ip']['buckets']:
                    for destinationIP in sourceIP['destination_ip']['buckets']:
                        
                        userName = {'User Name': response['key']}
                        event_url = {'URL': url['key']}
                        sourceAddress = {'Source IP Address': sourceIP['key']}
                        destinationAddress = {'Destination IP Address': destinationIP['key']}
                        event_count = {'Count': url['doc_count']}

                        blocked_alert_list.update(userName)
                        blocked_alert_list.update(event_url)
                        blocked_alert_list.update(sourceAddress)
                        blocked_alert_list.update(destinationAddress)
                        blocked_alert_list.update(event_count)

                        blocked_writer.writerow(blocked_alert_list)

    b.close()
    return

def allowed_url_filtering(firewall, organization):
    resp = client.search(index='haven*', body=firewall, size=5)
    # Todo: change file path
    with open('./Elastic_API/' + organization + '_Allowed_URLs.csv', 'w', newline='') as a:

        alert_list = {}
        blocked_columns = ['User Name', 'URL', 'Source IP Address', 'Destination IP Address', 'Count']
        writer = csv.DictWriter(a, fieldnames=blocked_columns)
        writer.writeheader()

        for response in resp['aggregations']['top_users']['buckets']:    
            for url in response['top_urls']['buckets']:
                for sourceIP in url['source_ip']['buckets']:
                    for destinationIP in sourceIP['destination_ip']['buckets']:
                        
                        userName = {'User Name': response['key']}
                        event_url = {'URL': url['key']}
                        sourceAddress = {'Source IP Address': sourceIP['key']}
                        destinationAddress = {'Destination IP Address': destinationIP['key']}
                        event_count = {'Count': url['doc_count']}

                        alert_list.update(userName)
                        alert_list.update(event_url)
                        alert_list.update(sourceAddress)
                        alert_list.update(destinationAddress)
                        alert_list.update(event_count)

                        writer.writerow(alert_list)

    a.close()
    return

def total_url_filtering(firewall, organization):
    resp = client.search(index='haven*', body=firewall_totals_query, size=0)
    alert_list = {}
    allowed_urls = 0
    blocked_urls = 0
    blocked_users = []
    # Todo: change file path
    with open('./Elastic_API/' + organization + '_URL_totals.csv', 'w', newline='') as f:
        blocked_columns = ['Total URLs', 'Total Blocked URLs', 'Total Allowed URLs', 'Count of Users (Blocked URLs)', 'Organization Name']
        writer = csv.DictWriter(f, fieldnames=blocked_columns)
        writer.writeheader()
        for response in resp['aggregations']['action']['buckets']:
            if "allowed" in response['key']:
                allowed_urls = response['doc_count']
                # print(allowed_urls)
            if "denied" in response['key']:
                for user in response['users']['buckets']:
                    blocked_urls = response['doc_count']
                    if user['key'] not in blocked_users:
                        blocked_users.append(user['key'])

        if resp['aggregations']['organization']['buckets'] == []:
            pass
        else:
            for response in resp['aggregations']['organization']['buckets']:
                organization_name = response['key']

        total_urls = {'Total URLs': allowed_urls + blocked_urls}
        total_blocked_urls = {'Total Blocked URLs': blocked_urls}
        total_allowed_urls = {'Total Allowed URLs': allowed_urls}
        users_blocked_urls = {'Count of Users (Blocked URLs)': len(blocked_users)}
        organziationName = {'Organization Name': organization_name}
        
        alert_list.update(total_urls)
        alert_list.update(total_blocked_urls)
        alert_list.update(total_allowed_urls)
        alert_list.update(users_blocked_urls)
        alert_list.update(organziationName)

        writer.writerow(alert_list)
    f.close()
    return

# Cylance function for threats.
def cylance_threats(cylance, organization):
    resp = client.search(index='haven*', body=cylance, size=0)
    # creating and opening the file for this definition.
    
    # Todo: change file paths
    with open('./Elastic_API/' + organization + '_Quarantined_Threats.csv', 'w', newline='') as q, open('./Elastic_API/' + organization + '_Allowed_Threats.csv', 'w', newline='') as a:
        quarantined_list = {}
        allowed_list = {}
        columns = ['Device Name', 'Event Action', 'File Path', 'File Name', 'Count']
        quarantined_writer = csv.DictWriter(q, fieldnames=columns)
        quarantined_writer.writeheader()

        allowed_writer = csv.DictWriter(a, fieldnames=columns)
        allowed_writer.writeheader()

    # This is the drill down to return the file information for allowed and quarantined alerts. 

        for action in resp['aggregations']['event_action']['buckets']: 
            if 'Abnormal' in action['key'] or 'Unsafe' in action['key'] or 'Waived' in action['key']:   
                for device in action['device_name']['buckets']:
                    for path in device['file_path']['buckets']:
                        for name in path['file_name']['buckets']:
                            allowed_file_path = path['key'].split(",", 1)
                            
                            device_name = {'Device Name': device['key']}
                            event_action = {'Event Action': action['key']}
                            file_path = {'File Path': allowed_file_path[0]}
                            file_name = {'File Name': name['key']}
                            allowed_count = {'Count': name['doc_count']}

                            allowed_list.update(device_name)
                            allowed_list.update(event_action)
                            allowed_list.update(file_path)
                            allowed_list.update(file_name)
                            allowed_list.update(allowed_count)

                            allowed_writer.writerow(allowed_list)
        # a.close()

            if 'Quarantined' in action['key'] or 'Cleared' in action['key']:
                for device in action['device_name']['buckets']:
                    for path in device['file_path']['buckets']:
                        for name in path['file_name']['buckets']:
                            quarantined_file_path = path['key'].split(",", 1)

                            device_name = {'Device Name': device['key']}
                            event_action = {'Event Action': action['key']}
                            file_path = {'File Path': quarantined_file_path[0]}
                            file_name = {'File Name': name['key']}
                            allowed_count = {'Count': name['doc_count']}

                            quarantined_list.update(device_name)
                            quarantined_list.update(event_action)
                            quarantined_list.update(file_path)
                            quarantined_list.update(file_name)
                            quarantined_list.update(allowed_count)

                            quarantined_writer.writerow(quarantined_list)
        q.close()
    return

# pulls the cylance exploit attempts for the client and outputs to a csv.
def cylance_exploits(cylance, organization):
    resp = client.search(index='haven*', body=cylance, size=0)
    # Todo: change file paths
    with open('./Elastic_API/' + organization + '_Allowed_Cylance_Exploits.csv', 'w', newline='') as a, open('./Elastic_API/' + organization + '_Blocked_Cylance_Exploits.csv', 'w', newline='') as b:
        allowed_alert_list = {}
        columns = ['Device Name', 'Process Name', 'Violation Type', 'Event Action', 'Count']
        allowed_writer = csv.DictWriter(a, fieldnames=columns)
        allowed_writer.writeheader()

        blocked_alert_list = {}
        blocked_writer = csv.DictWriter(b, fieldnames=columns)
        blocked_writer.writeheader()

        # drill down for exploits attempts both blocked and allowed.

        for action in resp['aggregations']['event_action']['buckets']: 
            if 'Blocked' in action['key']:
                for device in action['device_name']['buckets']:
                    for process in device['process_name']['buckets']:
                        for violation in process['violation_type']['buckets']:
                            device_name = {'Device Name': device['key']}
                            process_name = {'Process Name': process['key']}
                            violation_type =  {'Violation Type': violation['key']}
                            event_action = {'Event Action': action['key']}  
                            event_count = {'Count': process['doc_count']} 
                            
                            blocked_alert_list.update(device_name)
                            blocked_alert_list.update(process_name)
                            blocked_alert_list.update(violation_type)
                            blocked_alert_list.update(event_action)
                            blocked_alert_list.update(event_count)

                            blocked_writer.writerow(blocked_alert_list)


            if 'Blocked' not in action['key']:
                for device in action['device_name']['buckets']:
                    for process in device['process_name']['buckets']:
                        for violation in process['violation_type']['buckets']:

                            device_name = {'Device Name': device['key']}
                            process_name = {'Process Name': process['key']}
                            violation_type =  {'Violation Type': violation['key']}
                            event_action = {'Event Action': action['key']}  
                            event_count = {'Count': process['doc_count']} 
                            
                            allowed_alert_list.update(device_name)
                            allowed_alert_list.update(process_name)
                            allowed_alert_list.update(violation_type)
                            allowed_alert_list.update(event_action)
                            allowed_alert_list.update(event_count)

                            allowed_writer.writerow(allowed_alert_list)

    a.close()
    b.close()
    return

# pulls the cylance script control events and outputs to a seperate csv.
def cylance_scripts(cylance, organization):
    resp = client.search(index='haven*', body=cylance, size=0)

    # creating and opening the file for this definition.
    
    # Todo: change file path
    with open('./Elastic_API/' + organization + '_Cylance_Scripts.csv', 'w', newline='') as f:
        alert_list = {}
        columns = ['Device Name', 'File Path', 'File Hash', 'Script Type', 'Event Action', 'Count']
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()

        # drill down to get the script control alerts based on blocked or not.

        for action in resp['aggregations']['event_action']['buckets']: 
            for device in action['device_name']['buckets']:
                for path in device['file_path']['buckets']:
                    for interpreter in path['interpreter']['buckets']:
                        for hash in interpreter['file_hash']['buckets']:

                            device_name = {'Device Name': device['key']}
                            file_path = {'File Path': path['key']}
                            file_hash = {'File Hash': hash['key']}
                            type_of_script = {'Script Type': interpreter['key']}
                            event_action = {'Event Action': action['key']}
                            event_count = {'Count': path['doc_count']}

                            alert_list.update(device_name)
                            alert_list.update(file_path)
                            alert_list.update(file_hash)
                            alert_list.update(type_of_script)
                            alert_list.update(event_action)
                            alert_list.update(event_count)

                            writer.writerow(alert_list)
        

    f.close()
    return

# pulls the cylance device control events and outputs to a seperate csv.
def cylance_deviceControl(cylance, organization):
    resp = client.search(index='haven*', body=cylance, size=0)

    # creating and opening the file for this definition.
    
    # Todo: change file path
    with open('./Elastic_API/' + organization + '_Cylance_Device_Control.csv', 'w', newline='') as f:
        alert_list = {}
        columns = ['Device Name', 'USB Device Name', 'Device Serial Number', 'Event Action', 'Count']
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()

        # drill down for the device control events.

        for action in resp['aggregations']['event_action']['buckets']: 
            for device in action['device_name']['buckets']:
                for usb in device['usb_device']['buckets']:
                    for serial in usb['serial_num']['buckets']:

                        device_name = {'Device Name': device['key']}
                        usb_device_name = {'USB Device Name': usb['key']}
                        serial = {'Device Serial Number': serial['key']}
                        event_action = {'Event Action': action['key']}
                        event_count = {'Count': usb['doc_count']}

                        alert_list.update(device_name)
                        alert_list.update(usb_device_name)   
                        alert_list.update(serial)
                        alert_list.update(event_action)
                        alert_list.update(event_count)

                        writer.writerow(alert_list)                         

    f.close()
    return

# outputs to a csv, the total of each of the cylance events types.
def cylance_totals(cylance_total_devices, cylance_events, organization):
    total_devices = client.search(index='haven*', body=cylance_total_devices, size=0)
    total_events = client.search(index='haven*', body=cylance_events, size=0)

    # creating and opening the file for this definition.
        
    # Todo: change file path
    with open('./Elastic_API/' + organization + '_Cylance_totals.csv', 'w', newline='') as f:
        alert_list = {}
        columns = ['Total Events', 'Total Devices', 'Threats', 'Total Exploit Attempts', 'Total Script Control Events', 'Total Device Control Events', 'Total Quarantined Events', 'Total Allowed Executables', 'Unique Device Count (Threats Quarantined)', 'Unique Device Count (Threats Allowed)', 'Unique Device Count (Device Control)', 'Unique Device Count (ScriptControl)', 'Unique Device Count (Exploit Control)', 'Organization Name']
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        device_count = []
        threats = []
        threat_devices = []
        quarantined_threats = []
        quarantined_threats_devices = []
        allowed_threats = []
        allowed_threats_devices = []
        exploits = []
        exploits_devices = []
        scripts = []
        scripts_devices = []
        device_control = []
        device_control_devices = []
        client_name = ''

        for event in total_events['aggregations']['event_type']['buckets']:
            for device in event['devices']['buckets']:
                if 'Threat' in event['key']:
                    for action in device['action']['buckets']:
                        threats.append(action['doc_count'])
                        if "Quarantined" in action['key'] or 'Cleared' in action['key']:
                            quarantined_threats.append(action['doc_count'])
                            quarantined_threats_devices.append(action)
                        else:
                            allowed_threats.append(action['doc_count'])
                            allowed_threats_devices.append(action)
                if 'ExploitAttempt' in event['key']:
                    exploits_devices.append(device)
                    exploits.append(device['doc_count'])

        for event in total_events['aggregations']['other_event_type']['buckets']:
            for device in event['devices']['buckets']:
                if 'ScriptControl' in event['key']:
                    scripts_devices.append(device)
                    scripts.append(device['doc_count'])
                if 'DeviceControl' in event['key']:
                    device_control.append(device['doc_count'])
                    device_control_devices.append(device)

        for devices in total_devices['aggregations']['devices']['buckets']:
            device_count.append(device_count)

        if total_events['aggregations']['organization_name']['buckets'] == []:
            pass
        else:
            for org_name in total_events['aggregations']['organization_name']['buckets']:
                client_name = org_name['key']
                print(client_name)

        total_devices_count = {'Total Devices': len(device_count)}
        total_threats = {'Threats': sum(threats)}
        total_exploits = {'Total Exploit Attempts': sum(exploits)}
        total_scripts = {'Total Script Control Events': sum(scripts)}
        total_device_control = {'Total Device Control Events': sum(device_control)}
        total_quarantiend = {'Total Quarantined Events': sum(quarantined_threats)}
        total_allowed_executables = {'Total Allowed Executables': sum(allowed_threats)}
        total_quarantined_devices = {'Unique Device Count (Threats Quarantined)': len(quarantined_threats_devices)}
        total_allowed_devices = {'Unique Device Count (Threats Allowed)': len(allowed_threats_devices)}
        deviceControl_count = {'Unique Device Count (Device Control)': len(device_control_devices)}
        exploitAttempt_count = {'Unique Device Count (Exploit Control)': len(exploits_devices)}
        scriptControl_count = {'Unique Device Count (ScriptControl)': len(scripts_devices)}
        cylancePROTECT = {'Total Events': sum(threats) + sum(exploits) + sum(scripts) + sum(device_control)}
        organization_name = {'Organization Name': client_name}

        alert_list.update(cylancePROTECT)
        alert_list.update(total_devices_count)
        alert_list.update(total_threats)
        alert_list.update(total_exploits)
        alert_list.update(total_scripts)
        alert_list.update(total_device_control)
        alert_list.update(total_quarantiend)
        alert_list.update(total_allowed_executables)
        alert_list.update(total_quarantined_devices)
        alert_list.update(total_allowed_devices)
        alert_list.update(deviceControl_count)
        alert_list.update(exploitAttempt_count)
        alert_list.update(scriptControl_count)
        alert_list.update(organization_name)
        writer.writerow(alert_list)
    f.close()
    return

def mimecast(mimecast, organization):
    resp = client.search(index='mimecast*', body=mimecast, size=0)

    # creating and opening the file for this definition.
    
    # Todo: change file paths
    with open('./Elastic_API/' + organization + '_Mimecast_Header_Match.csv', 'w', newline='') as matched, open('./Elastic_API/' + organization + '_Mimecast_Header_No_Match.csv', 'w', newline='') as not_matched:
        matched_alert_list = {}
        not_matched_alert_list = {}
        columns = ['destination_email', 'source_email', 'header_from', 'subject', 'Count']
        matched_writer = csv.DictWriter(matched, fieldnames=columns)
        matched_writer.writeheader()

        not_matched_writer = csv.DictWriter(not_matched, fieldnames=columns)
        not_matched_writer.writeheader()

        for destination in resp['aggregations']['destination_email']['buckets']:
            for source in destination['source_email']['buckets']:
                for header in source['header_from']['buckets']:
                    if source['key'] == header['key']:
                        for subject in header['subject']['buckets']:

                            destination_email = {'destination_email': destination['key']}
                            source_email = {'source_email': source['key']}
                            header_from = {'header_from': header['key']}
                            email_subject = {'subject': subject['key']}
                            email_count = {'Count': source['doc_count']}

                            matched_alert_list.update(destination_email)
                            matched_alert_list.update(source_email)
                            matched_alert_list.update(header_from)
                            matched_alert_list.update(email_subject)
                            matched_alert_list.update(email_count)
                            
                            matched_writer.writerow(matched_alert_list)

                    if header['key'] != source['key']:
                        for subject in header['subject']['buckets']:

                            destination_email = {'destination_email': destination['key']}
                            source_email = {'source_email': source['key']}
                            header_from = {'header_from': header['key']}
                            email_subject = {'subject': subject['key']}
                            email_count = {'Count': source['doc_count']}

                            not_matched_alert_list.update(destination_email)
                            not_matched_alert_list.update(source_email)
                            not_matched_alert_list.update(header_from)
                            not_matched_alert_list.update(email_subject)
                            not_matched_alert_list.update(email_count)
                            
                            not_matched_writer.writerow(not_matched_alert_list)

    matched.close()
    not_matched.close()
    

    m = pd.read_csv('./Elastic_API/' + organization + '_Mimecast_Header_Match.csv').sort_values(by='Count', ascending=False)
    m.to_csv('./Elastic_API/' + organization + '_Mimecast_Header_Match_Sorted.csv', index=False)

    nm = pd.read_csv('./Elastic_API/' + organization + '_Mimecast_Header_No_Match.csv').sort_values(by='Count', ascending=False)
    nm.to_csv('./Elastic_API/' + organization + '_Mimecast_Header_No_Match_Sorted.csv', index=False)

    os.remove('./Elastic_API/' + organization + '_Mimecast_Header_Match.csv')
    os.remove('./Elastic_API/' + organization + '_Mimecast_Header_No_Match.csv')
    return

def mimecast_null_header(mimecast, organization):
    resp = client.search(index='mimecast*', body=mimecast, size=0)
    
    # Todo: change file path
    with open('./Elastic_API/' + organization + '_Mimecast_No_Header.csv', 'w', newline='') as no_header:
        alert_list = {}
        columns = ['destination_email', 'source_email', 'Count']
        writer = csv.DictWriter(no_header, fieldnames=columns)
        writer.writeheader()

        for destination in resp['aggregations']['destination_email']['buckets']:
            for source in destination['source_email']['buckets']:
                if source['subject']['doc_count_error_upper_bound'] == 0:

                    destination_email = {'destination_email': destination['key']}
                    source_email = {'source_email': source['key']}
                    count_of_emails = {'Count': source['doc_count']}

                    alert_list.update(destination_email)
                    alert_list.update(source_email)
                    alert_list.update(count_of_emails)

                    writer.writerow(alert_list)

                else: 
                    destination_email = {'destination_email': destination['key']}
                    source_email = {'source_email': source['key']}
                    count_of_emails = {'Count': source['doc_count']}

                    alert_list.update(destination_email)
                    alert_list.update(source_email)
                    alert_list.update(count_of_emails)

                    writer.writerow(alert_list)
    no_header.close()
    return

def fill_sheet(organization):
    # Todo: change file path
    input_file = pd.read_csv('./Elastic_API/Report_Data_Gathering.csv')
    # Todo: change file path
    with open('./Elastic_API/' + organization + '_' + str(report_month) + '_' + str(report_year) + '_Report_Data.csv', 'w') as f:
        # Todo: Change file paths
        cylanceTotals = pd.read_csv('./Elastic_API/' + organization + '_Cylance_totals.csv')
        cylanceDevices = pd.read_csv('./Elastic_API/' + organization + '_Cylance_Device_Control.csv')
        quarantinedThreats = pd.read_csv('./Elastic_API/' + organization + '_Quarantined_Threats.csv')
        allowedThreats = pd.read_csv('./Elastic_API/' + organization + '_Allowed_Threats.csv')
        firewall_Totals = pd.read_csv('./Elastic_API/' + organization + '_URL_totals.csv')
        allowed_URLS = pd.read_csv('./Elastic_API/' + organization + '_Allowed_URLs.csv')
        blocked_URLS = pd.read_csv('./Elastic_API/' + organization + '_Blocked_URLs.csv')
        cylanceScripts = pd.read_csv('./Elastic_API/' + organization + '_Cylance_Scripts.csv')
        mimecast_header_match = pd.read_csv('./Elastic_API/' + organization + '_Mimecast_Header_Match_Sorted.csv')
        mimecast_header_no_match = pd.read_csv('./Elastic_API/' + organization + '_Mimecast_Header_No_Match_Sorted.csv')
        mimecast_no_header = pd.read_csv('./Elastic_API/' + organization + '_Mimecast_No_Header.csv')

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
            input_file.iat[0, 2] = str(cylanceTotals.iloc[0,13])

        except IndexError:
            pass

            # Filling in totals for URLs

        try:
            input_file.iat[2,2] = str(firewall_Totals.iloc[0,0])
            input_file.iat[51,2] = str(firewall_Totals.iloc[0,0])
            # wks.update('C54', str(firewall_Totals.iloc[0,2])) count url's assocated with user per block
            input_file.iat[53,2] = str(firewall_Totals.iloc[0,2])
            input_file.iat[54,2] = str(firewall_Totals.iloc[0,3])
            input_file.iat[55,2] = str(firewall_Totals.iloc[0,2])

        except IndexError:
            pass

        # Table 2 and Table 4
        try:
            # Table 2
            input_file.iat[14,2] = str(cylanceDevices.iloc[0,0])
            input_file.iat[14,4] = str(cylanceDevices.iloc[0,4])
            input_file.iat[15,2] = str(cylanceDevices.iloc[1,0])
            input_file.iat[15,4] = str(cylanceDevices.iloc[1,4])
            input_file.iat[16,2] = str(cylanceDevices.iloc[2,0])
            input_file.iat[16,4] = str(cylanceDevices.iloc[2,4])
            input_file.iat[17,2] = str(cylanceDevices.iloc[3,0])
            input_file.iat[17,4] = str(cylanceDevices.iloc[3,4])
            input_file.iat[18,2] = str(cylanceDevices.iloc[4,0])
            input_file.iat[18,4] = str(cylanceDevices.iloc[4,4])

        except IndexError:
            # Table 2
            pass

        try:
            # Table 4
            input_file.iat[20,2] = str(cylanceDevices.iloc[0,0])
            input_file.iat[20,4] = str(cylanceDevices.iloc[0,1])
            input_file.iat[20,6] = str(cylanceDevices.iloc[0,4])
            input_file.iat[21,2] = str(cylanceDevices.iloc[1,0])
            input_file.iat[21,4] = str(cylanceDevices.iloc[1,1])
            input_file.iat[21,6] = str(cylanceDevices.iloc[1,4])
            input_file.iat[22,2] = str(cylanceDevices.iloc[2,0])
            input_file.iat[22,4] = str(cylanceDevices.iloc[2,1])
            input_file.iat[22,6] = str(cylanceDevices.iloc[2,4])
            input_file.iat[23,2] = str(cylanceDevices.iloc[3,0])
            input_file.iat[23,4] = str(cylanceDevices.iloc[3,1])
            input_file.iat[23,6] = str(cylanceDevices.iloc[3,4])
            input_file.iat[24,2] = str(cylanceDevices.iloc[4,0])
            input_file.iat[24,4] = str(cylanceDevices.iloc[4,1])
            input_file.iat[24,6] = str(cylanceDevices.iloc[4,4])

        except IndexError:
        #     Table 4
            pass
            

        # Filling the tables for Execution Control
        try:
            # Table 5
            input_file.iat[26,2] = str(quarantinedThreats.iloc[0,0])
            input_file.iat[26,4] = str(quarantinedThreats.iloc[0,2])
            input_file.iat[26,6] = str(quarantinedThreats.iloc[0,3])
            input_file.iat[26,8] = str(quarantinedThreats.iloc[0,4])
            input_file.iat[27,2] = str(quarantinedThreats.iloc[1,0])
            input_file.iat[27,4] = str(quarantinedThreats.iloc[1,2])
            input_file.iat[27,6] = str(quarantinedThreats.iloc[1,3])
            input_file.iat[27,8] = str(quarantinedThreats.iloc[1,4])
            input_file.iat[28,2] = str(quarantinedThreats.iloc[2,0])
            input_file.iat[28,4] = str(quarantinedThreats.iloc[2,2])
            input_file.iat[28,6] = str(quarantinedThreats.iloc[2,3])
            input_file.iat[28,8] = str(quarantinedThreats.iloc[2,4])
            input_file.iat[29,2] = str(quarantinedThreats.iloc[3,0])
            input_file.iat[29,4] = str(quarantinedThreats.iloc[3,2])
            input_file.iat[29,6] = str(quarantinedThreats.iloc[3,3])
            input_file.iat[29,8] = str(quarantinedThreats.iloc[3,4])
            input_file.iat[30,2] = str(quarantinedThreats.iloc[4,0])
            input_file.iat[30,4] = str(quarantinedThreats.iloc[4,2])
            input_file.iat[30,6] = str(quarantinedThreats.iloc[4,3])
            input_file.iat[30,8] = str(quarantinedThreats.iloc[4,4])

        except IndexError:
            pass
        
        try:
            # Table 6
            input_file.iat[32,2] = str(allowedThreats.iloc[0,0])
            input_file.iat[32,4] = str(allowedThreats.iloc[0,2])
            input_file.iat[32,6] = str(allowedThreats.iloc[0,3])
            input_file.iat[32,8] = str(allowedThreats.iloc[0,4])
            input_file.iat[33,2] = str(allowedThreats.iloc[1,0])
            input_file.iat[33,4] = str(allowedThreats.iloc[1,2])
            input_file.iat[33,6] = str(allowedThreats.iloc[1,3])
            input_file.iat[33,8] = str(allowedThreats.iloc[1,4])
            input_file.iat[34,2] = str(allowedThreats.iloc[2,0])
            input_file.iat[34,4] = str(allowedThreats.iloc[2,2])
            input_file.iat[34,6] = str(allowedThreats.iloc[2,3])
            input_file.iat[34,8] = str(allowedThreats.iloc[2,4])
            input_file.iat[35,2] = str(allowedThreats.iloc[3,0])
            input_file.iat[35,4] = str(allowedThreats.iloc[3,2])
            input_file.iat[35,6] = str(allowedThreats.iloc[3,3])
            input_file.iat[35,8] = str(allowedThreats.iloc[3,4])
            input_file.iat[36,2] = str(allowedThreats.iloc[4,0])
            input_file.iat[36,4] = str(allowedThreats.iloc[4,2])
            input_file.iat[36,6] = str(allowedThreats.iloc[4,3])
            input_file.iat[36,8] = str(allowedThreats.iloc[4,4])

        except IndexError:
            pass
 
        # Filling in Script Control Tables
        try:
            # Table 7
            input_file.iat[38,2] = str(cylanceScripts.iloc[0,0])
            input_file.iat[38,4] = str(cylanceScripts.iloc[0,1])
            input_file.iat[38,6] = str(cylanceScripts.iloc[0,3])
            input_file.iat[38,8] = str(cylanceScripts.iloc[0,5])
            input_file.iat[39,2] = str(cylanceScripts.iloc[1,0])
            input_file.iat[39,4] = str(cylanceScripts.iloc[1,1])
            input_file.iat[39,6] = str(cylanceScripts.iloc[1,3])
            input_file.iat[39,8] = str(cylanceScripts.iloc[1,5])
            input_file.iat[40,2] = str(cylanceScripts.iloc[2,0])
            input_file.iat[40,4] = str(cylanceScripts.iloc[2,1])
            input_file.iat[40,6] = str(cylanceScripts.iloc[2,3])
            input_file.iat[40,8] = str(cylanceScripts.iloc[2,5])
            input_file.iat[41,2] = str(cylanceScripts.iloc[3,0])
            input_file.iat[41,4] = str(cylanceScripts.iloc[3,1])
            input_file.iat[41,6] = str(cylanceScripts.iloc[3,3])
            input_file.iat[41,8] = str(cylanceScripts.iloc[3,5])
            input_file.iat[42,2] = str(cylanceScripts.iloc[4,0])
            input_file.iat[42,4] = str(cylanceScripts.iloc[4,1])
            input_file.iat[42,6] = str(cylanceScripts.iloc[4,3])
            input_file.iat[42,8] = str(cylanceScripts.iloc[4,5])

        except IndexError:
            pass
            
        try:
            # Table 8
            input_file.iat[44,2] = str(cylanceScripts.iloc[0,2])
            input_file.iat[44,4] = str(cylanceScripts.iloc[0,0])
            input_file.iat[44,6] = str(cylanceScripts.iloc[0,1])
            input_file.iat[44,8] = str(cylanceScripts.iloc[0,5])
            input_file.iat[45,2] = str(cylanceScripts.iloc[1,2])
            input_file.iat[45,4] = str(cylanceScripts.iloc[1,0])
            input_file.iat[45,6] = str(cylanceScripts.iloc[1,1])
            input_file.iat[45,8] = str(cylanceScripts.iloc[1,5])
            input_file.iat[46,2] = str(cylanceScripts.iloc[2,2])
            input_file.iat[46,4] = str(cylanceScripts.iloc[2,0])
            input_file.iat[46,6] = str(cylanceScripts.iloc[2,1])
            input_file.iat[46,8] = str(cylanceScripts.iloc[2,5])
            input_file.iat[47,2] = str(cylanceScripts.iloc[3,2])
            input_file.iat[47,4] = str(cylanceScripts.iloc[3,0])
            input_file.iat[47,6] = str(cylanceScripts.iloc[3,1])
            input_file.iat[47,8] = str(cylanceScripts.iloc[3,5])
            input_file.iat[48,2] = str(cylanceScripts.iloc[4,2])
            input_file.iat[48,4] = str(cylanceScripts.iloc[4,0])
            input_file.iat[48,6] = str(cylanceScripts.iloc[4,1])
            input_file.iat[48,8] = str(cylanceScripts.iloc[4,5])

        except IndexError:
            pass
        
        # # Filling in the Allowed URL section of the sheet.           
        try:
            input_file.iat[59,2] = str(allowed_URLS.iloc[0,1])
            input_file.iat[59,4] = str(allowed_URLS.iloc[0,4])
            input_file.iat[60,2] = str(allowed_URLS.iloc[1,1])
            input_file.iat[60,4] = str(allowed_URLS.iloc[1,4])
            input_file.iat[61,2] = str(allowed_URLS.iloc[2,1])
            input_file.iat[61,4] = str(allowed_URLS.iloc[2,4])
            input_file.iat[62,2] = str(allowed_URLS.iloc[3,1])
            input_file.iat[62,4] = str(allowed_URLS.iloc[3,4])
            input_file.iat[63,2] = str(allowed_URLS.iloc[4,1])
            input_file.iat[63,4] = str(allowed_URLS.iloc[4,4])

        except IndexError:
            pass

        #filling in the blocked URL Section

        # Filling in the Blocked URL section of the sheet.
        try:
            input_file.iat[65,2] = str(blocked_URLS.iloc[0,1])
            input_file.iat[65,4] = str(blocked_URLS.iloc[0,4])
            input_file.iat[66,2] = str(blocked_URLS.iloc[1,1])
            input_file.iat[66,4] = str(blocked_URLS.iloc[1,4])
            input_file.iat[67,2] = str(blocked_URLS.iloc[2,1])
            input_file.iat[67,4] = str(blocked_URLS.iloc[2,4])
            input_file.iat[68,2] = str(blocked_URLS.iloc[3,1])
            input_file.iat[68,4] = str(blocked_URLS.iloc[3,4])
            input_file.iat[69,2] = str(blocked_URLS.iloc[4,1])
            input_file.iat[69,4] = str(blocked_URLS.iloc[4,4])

        except IndexError:
            pass

        # Mimecast Section
        # Table 10
        try:
            input_file.iat[76,2] = str(mimecast_header_match.iloc[0,1])
            input_file.iat[76,4] = str(mimecast_header_match.iloc[0,2])
            input_file.iat[76,6] = str(mimecast_header_match.iloc[0,3])
            input_file.iat[76,8] = str(mimecast_header_match.iloc[0,4])
            input_file.iat[77,2] = str(mimecast_header_match.iloc[1,1])
            input_file.iat[77,4] = str(mimecast_header_match.iloc[1,2])
            input_file.iat[77,6] = str(mimecast_header_match.iloc[1,3])
            input_file.iat[77,8] = str(mimecast_header_match.iloc[1,4])
            input_file.iat[78,2] = str(mimecast_header_match.iloc[2,1])
            input_file.iat[78,4] = str(mimecast_header_match.iloc[2,2])
            input_file.iat[78,6] = str(mimecast_header_match.iloc[2,3])
            input_file.iat[78,8] = str(mimecast_header_match.iloc[2,4])
            input_file.iat[79,2] = str(mimecast_header_match.iloc[3,1])
            input_file.iat[79,4] = str(mimecast_header_match.iloc[3,2])
            input_file.iat[79,6] = str(mimecast_header_match.iloc[3,3])
            input_file.iat[79,8] = str(mimecast_header_match.iloc[3,4])
            input_file.iat[80,2] = str(mimecast_header_match.iloc[4,1])
            input_file.iat[80,4] = str(mimecast_header_match.iloc[4,2])
            input_file.iat[80,6] = str(mimecast_header_match.iloc[4,3])
            input_file.iat[80,8] = str(mimecast_header_match.iloc[4,4])

        except IndexError:
            pass

        # table 11
        try:
            input_file.iat[82,2] = str(mimecast_header_no_match.iloc[0,1])
            input_file.iat[82,4] = str(mimecast_header_no_match.iloc[0,2])
            input_file.iat[82,6] = str(mimecast_header_no_match.iloc[0,4])
            input_file.iat[83,2] = str(mimecast_header_no_match.iloc[1,1])
            input_file.iat[83,4] = str(mimecast_header_no_match.iloc[1,2])
            input_file.iat[83,6] = str(mimecast_header_no_match.iloc[1,4])
            input_file.iat[84,2] = str(mimecast_header_no_match.iloc[2,1])
            input_file.iat[84,4] = str(mimecast_header_no_match.iloc[2,2])
            input_file.iat[84,6] = str(mimecast_header_no_match.iloc[2,4])
            input_file.iat[85,2] = str(mimecast_header_no_match.iloc[3,1])
            input_file.iat[85,4] = str(mimecast_header_no_match.iloc[3,2])
            input_file.iat[85,6] = str(mimecast_header_no_match.iloc[3,4])
            input_file.iat[86,2] = str(mimecast_header_no_match.iloc[4,1])
            input_file.iat[86,4] = str(mimecast_header_no_match.iloc[4,2])
            input_file.iat[86,6] = str(mimecast_header_no_match.iloc[4,4])
        
        except IndexError:
            pass

        # table 12
        try:
            input_file.iat[88,2] = str(mimecast_no_header.iloc[0,1])
            input_file.iat[88,4] = str(mimecast_no_header.iloc[0,2])
            input_file.iat[89,2] = str(mimecast_no_header.iloc[1,1])
            input_file.iat[89,4] = str(mimecast_no_header.iloc[1,2])
            input_file.iat[89,2] = str(mimecast_no_header.iloc[2,1])
            input_file.iat[89,4] = str(mimecast_no_header.iloc[2,2])
            input_file.iat[90,2] = str(mimecast_no_header.iloc[3,1])
            input_file.iat[90,4] = str(mimecast_no_header.iloc[3,2])
            input_file.iat[91,2] = str(mimecast_no_header.iloc[4,1])
            input_file.iat[91,4] = str(mimecast_no_header.iloc[4,2])

        except IndexError:
            pass

        input_file.to_csv(f)

def create_month_report_folder():
    # Todo: change file path and make sure the google api secret file is named "client_secret.json"
    credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
    service = build('drive', 'v3', credentials=credentials)
    file_metadata = {
    'name': str(report_month) + '_' + str(report_year) + '_Reports',
    'mimeType': 'application/vnd.google-apps.folder',
    # Todo: change parent folder to main folder you want the monthly report folder to be in.
    'parents': ['1CkOwPmUeb6VdiqZScCu45SP_QBXN1Z1w']
    }
    file = service.files().create(body=file_metadata, fields='id').execute()

    page_token = None
    response = service.files().list(q="mimeType='application/vnd.google-apps.folder'", spaces='drive', fields='nextPageToken, files(id, name)', pageToken=page_token).execute()
    for file in response.get('files', []):
        if file.get('name') == str(report_month) + '_' + str(report_year) + '_Reports':
            file_id = file.get('id')
            print(file_id)
            return file_id

def create_client_google_folder(organization, parents: list=None):
    # Todo: change file path and make sure that the google api secret file is named "client_secret.json"
    credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
    service = build('drive', 'v3', credentials=credentials)
    file_metadata = {
    'name': organization + '_' + str(report_month) + '_' + str(report_year),
    'mimeType': 'application/vnd.google-apps.folder',
    'parents': [parents],
    }
    file = service.files().create(body=file_metadata, fields='id').execute()

    page_token = None
    response = service.files().list(q="mimeType='application/vnd.google-apps.folder'", spaces='drive', fields='nextPageToken, files(id, name)', pageToken=page_token).execute()
    for file in response.get('files', []):
        if file.get('name') == organization + '_' + str(report_month) + '_' + str(report_year):
            file_id = file.get('id')
            print(file_id)
            return file_id

def export_csv_file(organization, parents: list=None):
    # Todo: change file path
    file_path = './Elastic_API/' + organization + '_' + str(report_month) + '_' + str(report_year) + '_Report_Data.csv'
    # Todo: change file path and make sure the google client secret file is named "client_secret.json"
    credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
    service = build('drive', 'v3', credentials=credentials)
    # Todo: change file path and make sure the google client secret file is named "client_secret.json"
    sa = gspread.service_account(filename='./Elastic_API/client_secret.json')
    if not os.path.exists(file_path):
        print(f"{file_path} not found.")
        return
    try:
        sheet_metadata = {
            'name': organization + '_' + str(report_month) + '_' + str(report_year) + '_Report_Data',
            'mimetype': 'application/vnd.google-apps.spreadsheet',
            'parents': [parents]
        }
        sheet_media = MediaFileUpload(filename=file_path, mimetype='text/csv')

        sheet_response = service.files().create(media_body=sheet_media, body=sheet_metadata).execute()
        sheet_id = sheet_response.get('id')
        print(sheet_id)
        return sheet_id
    except Exception as e:
        print(e)
        return

def move_sheet_to_drive_folder(sheet_id, folder_id, organization):
    # Todo: change file path and make sure that the google secret file is named "client_secret.json"
    sa = gspread.service_account(filename='./Elastic_API/client_secret.json')
    sa.copy(file_id=sheet_id, title=organization + '_' + str(report_month) + '_' + str(report_year) + '_Report_Data', folder_id=folder_id)

if __name__ == "__main__":

    # this starts a timer that will be output for the total time it took to run all the reports for the list of clients.
    start = time.perf_counter()
    for client_id in organization_id:
        # creating the body of the firewall request to only pull url_filtering events.
        blocked_firewall_query = {
            "track_total_hits": True,
            "query": { 
            "bool": {
                "must": 
                [],
                    'filter': [
                        # Todo: change the time stamp. As it stands right now, a variable can not be in the path.
                        {'range': {'@timestamp': {'gte': report_start, 'lte': report_end, "format": "date_optional_time"}}},
                        {'match_phrase': {"organization.id": client_id}},
                        {'match_phrase': {'event.action': 'url_filtering'}},
                        {'match_phrase': {'observer.type': 'firewall'}},
                        {'match_phrase': {'event.type': "denied"}},
                        ]
                        }
                    },
                # top hits on top end users with blocked traffic
                "aggs": {
                    "top_users": {
                        "terms": {
                            "field": "client.user.name",
                            "size": 5,
                        }, # closes "terms"
                # in this aggregation, top 5 blocked URLs with count        
                    "aggs":{
                        "top_urls": {
                            "terms": {
                                "field": "url.original",
                                "size": 1,

                            }, # closes terms                   
                        "aggs": {                    
                            "source_ip": {
                                "terms": {
                                    "field": "source.ip",
                                    "size": 1,
                                        }, # closes terms in source ip
                            "aggs": {
                                "destination_ip": {
                                    "terms": {
                                        "field": "destination.ip",
                                        "size": 1,
                                    } # closes terms in destination_ip
                                } # closes destination_ip
                            }, # closes aggs for destination_ip
                                    } # closes source_ip
                                } # closses aggs of source_ip
                            }, # closes top_urls
                        } # closes aggs of top_urls
                    }, # closes "top_users"
                } # closes aggs of to_users
            }

        allowed_firewall_query = {
            "track_total_hits": True,
            "query": { 
            "bool": {
                "must": 
                [],
                    'filter': [
                        # Todo: change the time stamp. As it stands right now, a variable can not be in the path.
                        {'range': {'@timestamp': {'gte': report_start, 'lte': report_end, "format": "date_optional_time"}}},
                        {'match_phrase': {"organization.id": client_id}},
                        {'match_phrase': {'event.action': 'url_filtering'}},
                        {'match_phrase': {'observer.type': 'firewall'}},
                        {'match_phrase': {'event.type': "allowed"}},
                        ]
                        }
                    },
                # top hits on top end users with blocked traffic
                "aggs": {
                    "top_users": {
                        "terms": {
                            "field": "client.user.name",
                            "size": 5,
                        }, # closes "terms"
                # in this aggregation, top 5 blocked URLs with count        
                    "aggs":{
                        "top_urls": {
                            "terms": {
                                "field": "url.original",
                                "size": 1,

                            }, # closes terms                   
                        "aggs": {                    
                            "source_ip": {
                                "terms": {
                                    "field": "source.ip",
                                    "size": 1,
                                        }, # closes terms in source ip
                            "aggs": {
                                "destination_ip": {
                                    "terms": {
                                        "field": "destination.ip",
                                        "size": 1,
                                    } # closes terms in destination_ip
                                } # closes destination_ip
                            }, # closes aggs for destination_ip
                                    } # closes source_ip
                                } # closses aggs of source_ip
                            }, # closes top_urls
                        } # closes aggs of top_urls
                    }, # closes "top_users"
                } # closes aggs of to_users
            }

        firewall_totals_query = {
            "track_total_hits": True,
            "query": { 
            "bool": {
                "must": 
                [],
                    'filter': [
                        # Todo: change the time stamp. As it stands right now, a variable can not be in the path.
                        {'range': {'@timestamp': {'gte': report_start, 'lte': report_end, "format": "date_optional_time"}}},
                        {'match_phrase': {"organization.id": client_id}},
                        {'match_phrase': {'event.action': 'url_filtering'}},
                        {'match_phrase': {'observer.type': 'firewall'}},
                        ]
                        }
                    },
            "aggs": {
                "action": {
                    "terms": {
                        "field": 'event.type',
                        "size": 5,
                    }, # closes terms in action
                    "aggs": {
                        "users": {
                            "terms": {
                                "field": 'source.user.name',
                                "size": 10000,
                                }, # closes action
                            } # closes users under action
                    } # closes aggs for users under actoin
                }, # closes action
                "users": {
                    "terms": {
                        "field": 'source.user.name',
                        "size": 10000,
                    }, # closes terms for users
                    "aggs": {
                        "action": {
                            "terms": {
                                "field": 'event.type',
                                "size": 5,
                                }, # closes terms for action under users
                            } # closes action under users
                        } # closes aggs for action under users
                    }, # closes users   
                "organization": {
                    "terms": {
                        "field": 'organization.name'
                    } #closes terms for organization
                    } # closes organization
                } # closes top level aggs
            }

        # creating the cylance request body so that all api hits or narrowed to CylancePROTECT events.
        cylance_threats_query = {
            "track_total_hits": True,
            "query": { 
            "bool": {
                "must": 
                [],
                    'filter': [
                        # Todo: change the time stamp. As it stands right now, a variable can not be in the path.
                        {'range': {'@timestamp': {'gte': report_start, 'lte': report_end, "format": "date_optional_time"}}},
                        {'match_phrase': {"organization.id": client_id}},
                        {'match_phrase': {'event.module': 'CylancePROTECT'}},
                        # you can not do more than one cylance.event.type in a query as it breaks the query and always returns 0                
                        {'match_phrase': {'cylance.event.type': 'Threat'}},
                        ]
                        }
                    },
            # top devices with an event occurring on them with the filepath, and file name, event action will be filtered below.
            "aggs": {
                "event_action": {
                    "terms": {
                        "field": "event.action",
                        "size": 10,
                    }, # closes terms from event_action
                "aggs": {
                    "device_name": {
                        "terms" : {
                            "field": "observer.name",
                            "size": 5,
                        }, # closes tersm in device_name
                        "aggs": {
                            "file_path": {
                                "terms": {
                                    "field": "file.path",
                                    "size": 1,
                                }, # close terms for file_path
                            "aggs": {
                                "file_name": {
                                    "terms": {
                                        "field": "file.name",
                                        "size": 1,
                                    } # cloese terms for file_name
                                } # closes file_name
                            } # closes aggs for file_name
                            } # closes file_path
                        } # closes aggs for file_path
                    } # closes device_name
                } # closes aggs for device_name
                } # closes event_action
            }, # closes aggs from unique observers
        }

        cylance_exploits_query = {
            "track_total_hits": True,
            "query": { 
            "bool": {
                "must": 
                [],
                    'filter': [
                        # Todo: change the time stamp. As it stands right now, a variable can not be in the path.
                        {'range': {'@timestamp': {'gte': report_start, 'lte': report_end, "format": "date_optional_time"}}},
                        {'match_phrase': {"organization.id": client_id}},
                        {'match_phrase': {'event.module': 'CylancePROTECT'}},
                        # you can not do more than one cylance.event.type in a query as it breaks the query and always returns 0
                        {'match_phrase': {'cylance.event.type': 'ExploitAttempt'}},
                        ]
                        }
                    },
            # top devices with an event occurring on them with the filepath, and file name, event action will be filtered below.
            "aggs": {
                "event_action": {
                    "terms": {
                        "field": "event.action",
                        "size": 10,
                    }, # closes terms from event_action
                "aggs": {
                    "device_name": {
                        "terms": {
                            "field": "observer.name",
                            "size": 5,
                        }, # closes terms for device_name
                    "aggs": {
                        "process_name": {
                            "terms": {
                                "field": "process.name",
                                "size": 1,
                            }, # closes terms for process_name
                        "aggs": {
                            "violation_type": {
                                "terms": {
                                    "field": "cylance.violation_type",
                                    "size": 1,
                                }, # closes terms for violation_type
                            } # closes violation_type
                        } # closes aggs on violation_type
                        } # closes process_name
                    } # closes aggs for process_name
                    } # closes device_name
                } # closes aggs for device_name
                } # closes device_name
            }, # closes aggs from unique observers
        }

        cylance_scripts_query = {
            "track_total_hits": True,
            "query": { 
            "bool": {
                "must": 
                [],
                    'filter': [
                        # Todo: change the time stamp. As it stands right now, a variable can not be in the path.
                        {'range': {'@timestamp': {'gte': report_start, 'lte': report_end, "format": "date_optional_time"}}},
                        {'match_phrase': {"organization.id": client_id}},
                        {'match_phrase': {'event.module': 'CylancePROTECT'}},
                        # you can not do more than one cylance.event.type in a query as it breaks the query and always returns 0
                        {'match_phrase': {'cylance.event.type': 'ScriptControl'}},
                        ]
                        }
                    },
            # top devices with a script control event occurring on them with the filepath, and file hash, the interpreter that alerted on the event, and event action will be filtered below.
            "aggs": {
                "event_action": {
                    "terms": {
                        "field": "cylance.event.name",
                        "size": 5,
                    }, # closes terms for event_action
                "aggs": {
                    "device_name": {
                        "terms": {
                            "field": "observer.name",
                            "size": 5,
                        }, # closes terms for device_name
                    "aggs": {
                        "file_path": {
                            "terms": {
                                "field": "file.path",
                                "size": 1,
                            }, # closes terms for file_path
                        "aggs": {
                            "interpreter": {
                                "terms": {
                                    "field": "cylance.interpreter",
                                }, # closes terms for interpreter
                            "aggs": {
                                "file_hash": {
                                    "terms": {
                                        "field": "file.hash.sha256",
                                    } # closes terms in file_hash
                                } # closes file_hash
                            } # closes aggs for file_hash
                            } # closes interpreter
                        } # closes aggs for interpreter
                        } # closes terms for file_path
                    } # closes aggs for file_path
                    } # closes device_name
                } # closes aggs for device_name
                } # closes event_action
            } # closses aggs for event_action. 
        }

        cylance_device_query = {
            "track_total_hits": True,
            "query": { 
            "bool": {
                "must": 
                [],
                    'filter': [
                        # Todo: change the time stamp. As it stands right now, a variable can not be in the path.
                        {'range': {'@timestamp': {'gte': report_start, 'lte': report_end, "format": "date_optional_time"}}},
                        {'match_phrase': {"organization.id": client_id}},
                        {'match_phrase': {'event.module': 'CylancePROTECT'}},
                        # you can not do more than one cylance.event.type in a query as it breaks the query and always returns 0
                        {'match_phrase': {'cylance.event.type': 'DeviceControl'}},
                        ]
                        }
                    },
            # top devices with a script control event occurring on them with the filepath, and file hash, the interpreter that alerted on the event, and event action will be filtered below.
            "aggs": {
                "event_action": {
                    "terms": {
                        "field": "cylance.event.name",
                        "size": 5,
                    }, # closes terms for event_action
                "aggs": {
                    "device_name": {
                        "terms": {
                            "field": "observer.name",
                            "size": 5,
                        }, # closes terms for device_name
                    "aggs": {
                        "usb_device": {
                            "terms": {
                                "field": "cylance.device.name",
                                "size": 1,
                            }, # closes terms for usb_device
                        "aggs": {
                            "serial_num": {
                                "terms": {
                                    "field": "cylance.device.serial_number",
                                    "size": 1,
                                } # closes terms form serial_num
                            } # closes serial_num
                        } # closes aggs for serial_num
                        } # closes usb_device
                    } # closes aggs for usb_device
                    } # closes device_name
                } # closes aggs for device_name
                } # closes event_action
            } # closses aggs for event_action. 
        }

        cylance_total_devices_query = {
            "track_total_hits": True,
            "query": { 
            "bool": {
                "must": 
                [],
                    'filter': [
                        # Todo: change the time stamp. As it stands right now, a variable can not be in the path.
                        {'range': {'@timestamp': {'gte': report_start, 'lte': report_end, "format": "date_optional_time"}}},
                        {'match_phrase': {"organization.id": client_id}},
                        {'match_phrase': {'event.module': 'CylancePROTECT'}},
                        ]
                        }
                    },
            # total number of devices within a client's environment.
            "aggs": {
                "devices": {
                    "terms": {
                        "field": "observer.name",
                        "size": 10000
                    } # closes terms for devices
                } # closes devices
            }, # closes aggs from devices
        }

        cylance_total_events_query = {
            "track_total_hits": True,
            "query": { 
            "bool": {
                "must": 
                [],
                    'filter': [
                        # Todo: change the time stamp. As it stands right now, a variable can not be in the path.
                        {'range': {'@timestamp': {'gte': report_start, 'lte': report_end, "format": "date_optional_time"}}},
                        {'match_phrase': {"organization.id": client_id}},
                        {'match_phrase': {'event.module': 'CylancePROTECT'}},
                        ]
                        }
                    },
            # total number of devices within a client's environment.
            "aggs": {
                "event_type": {
                    "terms": {
                        "field": "cylance.event.type",
                        "size": 20
                    }, # closes terms for event_type
                "aggs": {
                    "devices": {
                        "terms": {
                            "field": "observer.name",
                            "size": 100000,
                        }, # closes terms for devices
                    "aggs": {
                        "action": {
                            "terms": {
                                "field": "event.action",
                                "size": 5,
                            }, # closes terms for action
                        } # closes action
                    } # closes aggs for action
                    } # closes devices
                } # closes aggs for devices
                }, # closes event_type
                "other_event_type": {
                    "terms": {
                        "field": "cylance.event.type",
                        "size": 20
                    }, # closes terms for event_type
                "aggs": {
                    "devices": {
                        "terms": {
                            "field": "observer.name",
                            "size": 100000,
                        }, # closes terms for devices
                    "aggs": {
                        "action": {
                            "terms": {
                                "field": "cylance.event.name",
                                "size": 5,
                            }, # closes terms for action
                        } # closes action
                    } # closes aggs for action
                    } # closes devices
                } # closes aggs for devices
                }, # closes event_type
                "organization_name": {
                    "terms": {
                        "field": "organization.name",
                        "size": 1,
                    } # closes terms.
                } # closes organization name
            }, # closes aggs from event_type
        }

        # creating the mimecast request body so that all api hits are narrowed to Mimdcast events.
        mimecast_query = {
            "track_total_hits": True,
            "query": {
                "bool": {
                    "must": [],
                        "filter": [
                        # Todo: change the time stamp. As it stands right now, a variable can not be in the path.
                            {'range': {'@timestamp': {'gte': report_start, 'lte': report_end, "format": "date_optional_time"}}},
                            {'match_phrase': {"organization.id.keyword": client_id}},
                            {'match_phrase': {'event.module': 'mimecast'}},
                            {'match_phrase': {'mimecast.event_type': 'receipt'}},
                            {'match_phrase': {'network.direction': 'Inbound'}},
                            {'match_phrase': {'event.action': 'Acc'}}
                        ],
                    "must_not": {
                            'match_phrase': {'mimecast.sender.domain': 'zendesk.com'},
                            'match_phrase': {'mimecast.sender.domain': 'amazonses.com'},
                            'match_phrase': {'mimecast.sender.domain': 'atlassian.net'},
                            'match_phrase': {'mimecast.sender.domain': 'us-east-2.amazonses.com'}   
                    }                 
                }
            },
            "aggs": {
                "destination_email": {
                    "terms": {
                        "field": 'destination.user.email.keyword',
                        "size": 10000,
                    }, # closes terms for destination_email
                "aggs": {
                    "source_email": {
                        "terms": {
                            "field": "source.user.email.keyword",
                            "size": 10000,
                        }, # closes terms for sender_domain
                    "aggs": {
                        "header_from": {
                            "terms": {
                                "field": "mimecast.header_from",
                                "size": 10000,
                            }, # closes terms in header_from
                        "aggs": {
                            "subject": {
                                "terms": {
                                    "field": "mimecast.subject",
                                    "size": 1,
                                } # closes terms for subject
                            } # closes subject
                        } # closes aggs for subject
                        } # cloases header_from
                    } # closes aggs for header_from
                    } # closes sender_domain
                } # closes sender_domain
                } # closes destination_email
            } # closes aggs for destination_email
        }

        mimecast_null_header_query = {
            "track_total_hits": True,
            "query": {
                "bool": {
                    "must": [],
                        "filter": [
                        # Todo: change the time stamp. As it stands right now, a variable can not be in the path.
                            {'range': {'@timestamp': {'gte': report_start, 'lte': report_end, "format": "date_optional_time"}}},
                            {'match_phrase': {"organization.id.keyword": client_id}},
                            {'match_phrase': {'event.module': 'mimecast'}},
                            {'match_phrase': {'mimecast.event_type': 'receipt'}},
                            {'match_phrase': {'network.direction': 'Inbound'}},
                            {'match_phrase': {'event.action': 'Acc'}}
                        ],
                    "must_not": [{
                            'match_phrase': {'mimecast.sender.domain': 'zendesk.com'},
                            'match_phrase': {'mimecast.sender.domain': 'amazonses.com'},
                            'match_phrase': {'mimecast.sender.domain': 'atlassian.net'},
                            'match_phrase': {'mimecast.sender.domain': 'us-east-2.amazonses.com'},
                    },
                    {'exists': {'field': "mimecast.header_from"}}]                 
                }
            },
            "aggs": {
                "destination_email": {
                    "terms": {
                        "field": 'destination.user.email.keyword',
                        "size": 10000,
                    }, # closes terms for destination_email
                "aggs": {
                    "source_email": {
                        "terms": {
                            "field": "source.user.email.keyword",
                            "size": 10000,
                        }, # closes terms for sender_domain
                    "aggs": {
                        "subject": {
                            "terms": {
                                "field": "mimecast.subject",
                                "size": 1,
                            } # closes terms for subject
                        } # closes subject
                    } # closes aggs for subject
                    } # closes sender_domain
                } # closes sender_domain
                }, # closes destination_email
            } # closes aggs for destination_email
        }

        # creating the threads for each of the queries to be called.
        blocked_url = threading.Thread(target=blocked_url_filtering, args=[blocked_firewall_query, client_id])
        allowed_url = threading.Thread(target=allowed_url_filtering , args=[allowed_firewall_query, client_id])
        total_url = threading.Thread(target=total_url_filtering , args=[firewall_totals_query, client_id])
        cylanceThreats = threading.Thread(target=cylance_threats , args=[cylance_threats_query, client_id])
        cylanceExploits = threading.Thread(target=cylance_exploits , args=[cylance_exploits_query, client_id])
        cylanceScripts = threading.Thread(target=cylance_scripts , args=[cylance_scripts_query, client_id])
        cylanceDevice = threading.Thread(target=cylance_deviceControl , args=[cylance_device_query, client_id])
        cylanceTotals = threading.Thread(target=cylance_totals , args=[cylance_total_devices_query,cylance_total_events_query, client_id])            
        mimecastHeaders = threading.Thread(target=mimecast , args=[mimecast_query, client_id])
        mimecastNoHeaders = threading.Thread(target=mimecast_null_header , args=[mimecast_null_header_query, client_id])

        # starting each thread to run congruently.
        blocked_url.start()
        allowed_url.start()
        total_url.start()
        cylanceThreats.start()
        cylanceExploits.start()
        cylanceScripts.start()
        cylanceDevice.start()
        cylanceTotals.start()
        mimecastHeaders.start()
        mimecastNoHeaders.start()

        # joining the threads to the active process so that they may run congruently.
        blocked_url.join()
        allowed_url.join()
        total_url.join()
        cylanceThreats.join()
        cylanceExploits.join()
        cylanceScripts.join()
        cylanceDevice.join()
        cylanceTotals.join()
        mimecastHeaders.join()
        mimecastNoHeaders.join()

        # Filling in the sheet based of the csv's that were pulled in the above threading action
        fill_sheet(client_id)
        # Todo: Change file paths
        #removing the csv's for each individual aggregation pull now that the report csv has been created.
        folder = './Elastic_API/'
        files = [client_id + '_Allowed_Cylance_Exploits.csv', 
            client_id + '_Allowed_Threats.csv', 
            client_id +'_Allowed_URLs.csv', 
            client_id + '_Blocked_Cylance_Exploits.csv', 
            client_id + '_Blocked_URLs.csv', 
            client_id + '_Cylance_Device_Control.csv', 
            client_id + '_Cylance_Scripts.csv', 
            client_id + '_Cylance_totals.csv', 
            client_id + '_Mimecast_Header_Match_Sorted.csv', 
            client_id + '_Mimecast_Header_No_Match_Sorted.csv',
            client_id + '_Mimecast_No_Header.csv',
            client_id + '_Quarantined_Threats.csv',
            client_id + '_URL_totals.csv',
            ]

        for file in files:
            try:
                os.remove(folder + file)
            except FileNotFoundError:
                pass

    # create the current month folder for the reports that are being run.
    month_folder = str(create_month_report_folder())
    # iterating over the clients in the list of clients to create their own folders and upload the report csv to that folder.
    for client in organization_id:
        folder_id = str(create_client_google_folder(client, month_folder))
        sheet_id = str(export_csv_file(client, folder_id))
        move_sheet_to_drive_folder(sheet_id, folder_id, client)

    # this will output the total time it took to complete all the above tasks.
    finish = time.perf_counter()
    print(f'Finished in {round(finish-start), 2} seconds')
