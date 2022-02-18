from elasticsearch import Elasticsearch
import json
import csv
import gspread
import pandas as pd
import os.path
from oauth2client.service_account import ServiceAccountCredentials
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from datetime import datetime

currentMonth = datetime.now().month
currentYear = datetime.now().year

credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
service = build('drive', 'v3', credentials=credentials)
page_token = None
response = service.files().list(q="mimeType='application/vnd.google-apps.folder'", spaces='drive', fields='nextPageToken, files(id, name)', pageToken=page_token).execute()
for file in response.get('files', []):
    if file.get('name') == 'aaaam4_' + str(currentMonth) + '_' + str(currentYear):
        
        sa = gspread.service_account(filename='./Elastic_API/client_secret.json')
        report = sa.open(str(file.get('name')))
        wks = report.worksheet('Sheet1')
        allowedThreats = pd.read_csv('./Elastic_API/aaaam4_Allowed_Threats.csv')

                

        try:
            wks.update('C34', str(allowedThreats.iloc[0,1]))
            wks.update('E34', str(allowedThreats.iloc[0,4]))
            wks.update('G34', str(allowedThreats.iloc[0,5]))
            wks.update('I34', str(allowedThreats.iloc[0,6]))
            wks.update('C35', str(allowedThreats.iloc[1,1]))
            wks.update('E35', str(allowedThreats.iloc[1,4]))
            wks.update('G35', str(allowedThreats.iloc[1,5]))
            wks.update('I35', str(allowedThreats.iloc[1,6]))
            wks.update('C36', str(allowedThreats.iloc[2,1]))
            wks.update('E36', str(allowedThreats.iloc[2,4]))
            wks.update('G36', str(allowedThreats.iloc[2,5]))
            wks.update('I36', str(allowedThreats.iloc[2,6]))
            wks.update('C37', str(allowedThreats.iloc[3,1]))
            wks.update('E37', str(allowedThreats.iloc[3,4]))
            wks.update('G37', str(allowedThreats.iloc[3,5]))
            wks.update('I37', str(allowedThreats.iloc[3,6]))
            wks.update('C38', str(allowedThreats.iloc[4,1]))
            wks.update('E38', str(allowedThreats.iloc[4,4]))
            wks.update('G38', str(allowedThreats.iloc[4,5]))
            wks.update('I38', str(allowedThreats.iloc[4,6]))


        except IndexError:
            wks.update('C34', 'N/A')
            wks.update('E34', 'N/A')
            wks.update('G34', 'N/A')
            wks.update('I34', 'N/A')
            wks.update('C35', 'N/A')
            wks.update('E35', 'N/A')
            wks.update('G35', 'N/A')
            wks.update('I35', 'N/A')
            wks.update('C36', 'N/A')
            wks.update('E36', 'N/A')
            wks.update('G36', 'N/A')
            wks.update('I36', 'N/A')
            wks.update('C37', 'N/A')
            wks.update('E37', 'N/A')
            wks.update('G37', 'N/A')
            wks.update('I37', 'N/A')
            wks.update('C38', 'N/A')
            wks.update('E38', 'N/A')
            wks.update('G38', 'N/A')
            wks.update('I38', 'N/A')








# client = Elasticsearch(
#     "https://lb-es.rocusnetworks.local:9200",
#     verify_certs=False,
#     api_key=("hjaqT34BIH6T_vw3S4tj", "ixuZn8myQfCjJlEIciVB3g"),
#     timeout=60,
# )

# cylance_query = {
#     "query": {
#         "bool": {
#             "must": [],
#                 "filter": [
#                     {'range': {'@timestamp': {'gte': '2021-11-02T05:00:00.000Z', 'lte': '2021-12-01T05:00:00.000Z', "format": "strict_date_optional_time"}}},
#                     {'match_phrase': {"organization.id": 'aaaam4'}},
#                     {'match_phrase': {'event.module': 'CylancePROTECT'}},
#                 ]
#         }
#     }
# }

# resp = client.search(index='haven*', body=cylance_query, size=10000)
# # print(resp['hits']['total']['value'])
# scriptControl_deviceName = []
# for hit in resp['hits']['hits']:
#     event_type = hit['_source']['cylance']['event']['type']
#     # print(hit['_source']['cylance']['event']['type'])
#     if event_type == 'ScriptControl':
#         for observer in hit['_source']['observer']['name']:
#             if observer not in scriptControl_deviceName:
#                 scriptControl_deviceName.append(observer)

# print(scriptControl_deviceName)
# print(resp['hits']['total']['value'])

# device_count = []
# events = []
# for hit in resp['hits']['hits']:
#     event_type = hit['_source']['cylance']['event']['type']
#     if event_type  not in events:
#         events.append(event_type)
# # print(events)

# for hit in resp['hits']['hits']:
#     try:
#         for observer in hit['_source']['observer']['name']:
#             if observer not in device_count:
#                 device_count.append(observer)
#     except KeyError:
#         continue
    
#         # if observer not in device_count:
#         #     device_count.append(observer)


# print(device_count, len(device_count))
    



