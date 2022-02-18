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

client = Elasticsearch(
    "https://lb-es.rocusnetworks.local:9200",
    verify_certs=False,
    api_key=("hjaqT34BIH6T_vw3S4tj", "ixuZn8myQfCjJlEIciVB3g"),
    timeout=60,
)


firewall_query = {
	"query": {
	"bool": {
		"must": 
        [],
			'filter': [
				{'range': {'@timestamp': {'gte': '2022-02-01T05:00:00.000Z', 'lte': '2022-02-15T05:00:00.000Z', "format": "strict_date_optional_time"}}},
                {'match_phrase': {"organization.id": 'aaaag1'}},
                {'match_phrase': {'event.action': 'url_filtering'}},
                {'match_phrase': {'observer.type': 'firewall'}},
				]
				}
			}
		}


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

    url_filtering(firewall_query)