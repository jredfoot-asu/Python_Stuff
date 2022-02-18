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

report_month = 0
report_year = 0

if currentMonth == 1:
    report_month = 12
    report_year = currentYear -1
else:
    report_month = currentMonth - 1
    report_year = currentYear

credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
service = build('drive', 'v3', credentials=credentials)

# Create folder for the client's data
# file_metadata = {
#     'name': 'Clients',
#     'mimeType': 'application/vnd.google-apps.folder',
#     'parents': ['1zYOfDeW49A5n6eqOUpZ0lnAlB-eAOaRv']
# }
# file = service.files().create(body=file_metadata, fields='id').execute()

# Setup the service to search for a file name.
page_token = None
folder_response = response = service.files().list(q="mimeType='application/vnd.google-apps.folder'", spaces='drive', fields='nextPageToken, files(id, name)', pageToken=page_token).execute()
sheet_response = service.files().list(q="mimeType='application/vnd.google-apps.spreadsheet'", spaces='drive', fields='nextPageToken, files(id, name)', pageToken=page_token).execute()
# print(response)

# Delete a file.
fileDelete = '1tPfBxHAnUT8Ln8M1LhdnjqTQTOWjzPnI'
# file = service.files().delete(fileId=fileDelete).execute()


# Search All  Folders
# request_body = {
#     'role': 'writer',
#     'type': 'anyone'
# }

for file in folder_response.get('files', []):
    # print ('Found file: %s (%s)' % (file.get('name'), file.get('id')))
    # if file.get('name') == organization_id + '_' + str(currentMonth) + '_' + str(currentYear) + '_Report_Data':
    if file.get('name') == str(report_month) + '_' + str(report_year) + '_Reports':
        # permissions = file.permissions().create(fileId=file.get('id'), body=request_body).execute()
        file_ID = file.get('id')
        service.files().delete(fileId=file_ID).execute()
        print('Folders: \n', file)

for file in folder_response.get('files', []):
    # print ('Found file: %s (%s)' % (file.get('name'), file.get('id')))
    # if file.get('name') == organization_id + '_' + str(currentMonth) + '_' + str(currentYear) + '_Report_Data':
    if file.get('name') == organization_id + '_' + str(report_month) + '_' + str(report_year):
        # permissions = file.permissions().create(fileId=file.get('id'), body=request_body).execute()
        file_ID = file.get('id')
        service.files().delete(fileId=file_ID).execute()
        print('Folders: \n', file)

for file in sheet_response.get('files', []):    
    if file.get('name') == organization_id + '_' + str(report_month) + '_' + str(report_year) + '_Report_Data':
        # file_ID = file.get('id')
        # service.files().delete(fileId=file_ID).execute()
        print('Files: \n',file)