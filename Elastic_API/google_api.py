import os
import httplib2
from Google import Create_Service
from apiclient import discovery

CLIENT_SECRET_FILE = './Elastic_API/client_secret.json'
API_Name = 'Reporting'
API_VERSION = 'v4'
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

# print(os.getcwd())

service = Create_Service(CLIENT_SECRET_FILE, API_Name, API_VERSION, SCOPES)
print(dir(service))

# def main(key='AIzaSyDGjh5dBi2roz2Xa9KPGhMXHQgXDmILLws'):
#     discoveryUrl = 'https://www.googleapis.com/auth/spreadsheets'
#     service = discovery.build(
#         API_Name,
#         API_VERSION,
#         http=httplib2.Http(),
#         discoveryServiceUrl=discoveryUrl,
#         developerKey=key)

#     spreadsheetId = '1lXiS3IbrYPgf5D7K0Nx29CNlfOFaiIzgg1nP8p7jR40'
#     rangeName = 'Class Data!A2:E'
#     result = service.spreadsheets().values().get(
#         spreadsheetId=spreadsheetId, range=rangeName).execute()
#     values = result.get('values', [])
    
#     if not values:
#         print('No data found.')
#     else:
#         print('Name, Major:')
#         for row in values:
#             # Print columns A and E, which correspond to indices 0 and 4.
#             print('%s, %s' % (row[0], row[4]))


# if __name__ == '__main__':
#     from sys import argv

#     if len(argv) == 2:
#         main(key=argv[1])
#     else:
#         main()