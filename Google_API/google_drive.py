import os.path
from oauth2client.service_account import ServiceAccountCredentials
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

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
response = service.files().list(q="mimeType='application/vnd.google-apps.folder'", spaces='drive', fields='nextPageToken, files(id, name)', pageToken=page_token).execute()
# print(response)

# Delete a file.
# fileDelete = '1AGuFDNU-b0qdKDTjdUYNbN1uvvagqxZ-'
# file = service.files().delete(fileId=fileDelete).execute()


# Search All  Folders
# request_body = {
#     'role': 'writer',
#     'type': 'anyone'
# }
for file in response.get('files', []):
    # print ('Found file: %s (%s)' % (file.get('name'), file.get('id')))
    if file.get('name') == 'Clients':
        # permissions = file.permissions().create(fileId=file.get('id'), body=request_body).execute()
        # print(permissions)
        # link = file().get('id', fields='webViewLink').execute()
        # print(link)
        
