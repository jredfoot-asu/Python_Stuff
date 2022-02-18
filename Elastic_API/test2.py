from elasticsearch import Elasticsearch
import json
import csv
import pandas as pd
import os
import time
import threading
import concurrent.futures
from oauth2client.service_account import ServiceAccountCredentials
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload
from datetime import datetime

import gspread

currentMonth = datetime.now().month
currentYear = datetime.now().year
organization_id = 'aaaam4'


report_month = 0
report_year = 0

if currentMonth == 1:
    report_month = 12
    report_year = currentYear -1
else:
    report_month = currentMonth - 1
    report_year = currentYear

file_path = './Elastic_API/' + organization_id + '_' + str(report_month) + '_' + str(report_year) + '_Report_Data.csv'

def create_month_report_folder():
    credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
    service = build('drive', 'v3', credentials=credentials)
    file_metadata = {
    'name': str(report_month) + '_' + str(report_year) + '_Reports',
    'mimeType': 'application/vnd.google-apps.folder',
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

def create_client_google_folder():
    credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
    service = build('drive', 'v3', credentials=credentials)
    file_metadata = {
    'name': organization_id + '_' + str(report_month) + '_' + str(report_year),
    'mimeType': 'application/vnd.google-apps.folder',
    'parents': ['1CkOwPmUeb6VdiqZScCu45SP_QBXN1Z1w'],
    }
    file = service.files().create(body=file_metadata, fields='id').execute()

    page_token = None
    response = service.files().list(q="mimeType='application/vnd.google-apps.folder'", spaces='drive', fields='nextPageToken, files(id, name)', pageToken=page_token).execute()
    for file in response.get('files', []):
        if file.get('name') == organization_id + '_' + str(report_month) + '_' + str(report_year):
            file_id = file.get('id')
            print(file_id)
            return file_id

def export_csv_file(file_path: str, parents: list=None,):
    credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
    service = build('drive', 'v3', credentials=credentials)
    sa = gspread.service_account(filename='./Elastic_API/client_secret.json')
    if not os.path.exists(file_path):
        print(f"{file_path} not found.")
        return
    try:
        sheet_metadata = {
            'name': organization_id + '_' + str(report_month) + '_' + str(report_year) + '_Report_Data',
            'mimetype': 'application/vnd.google-apps.spreadsheet',
            'parents': [parents]
        }
        sheet_media = MediaFileUpload(filename=file_path, mimetype='text/csv')

        sheet_response = service.files().create(media_body=sheet_media, body=sheet_metadata).execute()
        sheet_id = sheet_response.get('id')
        print(sheet_id)
        sa.copy(file_id=sheet_id, title=organization_id + '_' + str(report_month) + '_' + str(report_year) + '_Report_Data.csv', folder_id=parents)
        return sheet_id
    except Exception as e:
        print(e)
        return

def move_sheet_to_drive_folder(sheet_id, folder_id):
    sa = gspread.service_account(filename='./Elastic_API/client_secret.json')
    sa.copy(file_id=sheet_id, title=organization_id + '_' + str(report_month) + '_' + str(report_year) + '_Report_Data.csv', folder_id=folder_id)



# create_google_folder()
# create_month_report_folder()
# folder_id = str(create_client_google_folder())

# export_csv_file(file_path, folder_id)
# print(sheet_id, type(sheet_id), folder_id, type(folder_id))
# print(sheet_id, type(sheet_id), folder_id, type(folder_id))

export_csv_file(file_path, str(create_client_google_folder()))


# time.sleep(5)
# remove_uneeded_cols_rows()









# def export_csv_file(file_path: str, parents: list=None,):
#     credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
#     service = build('drive', 'v3', credentials=credentials)
#     sa = gspread.service_account(filename='./Elastic_API/client_secret.json')
#     if not os.path.exists(file_path):
#         print(f"{file_path} not found.")
#         return
#     try:
#         sheet_metadata = {
#             'name': organization_id + '_' + str(currentMonth) + '_' + str(currentYear) + '_Report_Data',
#             'mimetype': 'application/vnd.google-apps.spreadsheet',
#         }
#         sheet_media = MediaFileUpload(filename=file_path, mimetype='text/csv')

#         sheet_response = service.files().create(media_body=sheet_media, body=sheet_metadata).execute()
#         sheet_id = sheet_response.get('id')
#         print(sheet_id)
#         return sheet_id

#     except Exception as e:
#         print(e)
#         return

# def create_google_folder():
#     credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
#     service = build('drive', 'v3', credentials=credentials)
#     file_metadata = {
#     'name': organization_id + '_' + str(currentMonth) + '_' + str(currentYear),
#     'mimeType': 'application/vnd.google-apps.folder',
#     'parents': ['1CkOwPmUeb6VdiqZScCu45SP_QBXN1Z1w']
#     }
#     file = service.files().create(body=file_metadata, fields='id').execute()

#     page_token = None
#     response = service.files().list(q="mimeType='application/vnd.google-apps.folder'", spaces='drive', fields='nextPageToken, files(id, name)', pageToken=page_token).execute()
#     for file in response.get('files', []):
#         if file.get('name') == organization_id + '_' + str(currentMonth) + '_' + str(currentYear):
#             file_id = file.get('id')
#             print(file_id)
#             return file_id

# def move_sheet_to_drive_folder(sheet_id, folder_id):
#     sa = gspread.service_account(filename='./Elastic_API/client_secret.json')
#     sa.copy(file_id=sheet_id, title=organization_id + '_' + str(currentMonth) + '_' + str(currentYear) + '_Report_Data.csv', folder_id=folder_id)


# def remove_uneeded_cols_rows():
    # credentials = ServiceAccountCredentials.from_json_keyfile_name('./Elastic_API/client_secret.json')
    # drive_service = build('drive', 'v3', credentials=credentials)

    # page_token = None
    # drive_response = drive_service.files().list(q="mimeType='application/vnd.google-apps.spreadsheet'", spaces='drive', fields='nextPageToken, files(id, name)', pageToken=page_token).execute()

    # for file in drive_response.get('files', []):
    #     if file.get('name') == organization_id + '_' + str(currentMonth) + '_' + str(currentYear) + '_Report_Data':
    #         print(file.get('id'), file.get('name'))
    #         sa = gspread.service_account(filename='./Elastic_API/client_secret.json')
    #         sh = sa.open(str(file.get('name')))
    #         request = {
    #             "requests": [
    #                 {
    #                     "deleteDimension": {
    #                         "range": {
    #                             "sheetId": str(file.get('id')),
    #                             "dimension": "COLUMNS",
    #                             "startIndex": 0,
    #                             "endIndex": 1
    #                         }
    #                     }
    #                 }
    #             ]
    #         }
    #         sh.batch_update(request)






# # create_google_folder()
# folder_id = str(create_google_folder())

# sheet_id = str(export_csv_file(file_path, folder_id))
# # print(sheet_id, type(sheet_id), folder_id, type(folder_id))
# # print(sheet_id, type(sheet_id), folder_id, type(folder_id))
# move_sheet_to_drive_folder(sheet_id, folder_id)
# time.sleep(5)
# remove_uneeded_cols_rows()
