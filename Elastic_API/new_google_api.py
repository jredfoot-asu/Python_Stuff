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

organization_id = 'aaaam4'
currentMonth = datetime.now().month
currentYear = datetime.now().year

sa = gspread.service_account(filename='./Elastic_API/client_secret.json')
sh = sa.open('Master Copy - Data Gathering')

# wks = sh.worksheet('Sheet1')

# print('Rows ', wks.row_count)
# print('Cols ', wks.row_count)

# print(wks.acell('A9').value)
# print(wks.cell(3, 3).value)
# print(wks.get('A7:E9'))
# print(wks.get_all_records())

# wks.update('C3', 'Fill-Out')
# wks.update('D4', '=UPPER(C4)', raw=False)

# wks.delete_rows(75)

# report = sa.create('aaaam4')
# report.share('jason.redfoot@corvidtec.com', perm_type='user', role='writer')
# copy = wks.get_all_records()
# report = sa.open('aaaam4')
# aaaam4 = report.worksheet('Sheet1')
# aaaam4.update('A1:I71', copy)
# sa.del_spreadsheet('aaaam4')

sa.copy(file_id='1jnUb2EJaBbLVWOXZCCj5CQUdVGCm47e_', title=organization_id + '_' + str(currentMonth) + '_' + str(currentYear) + '_Report_Data.csv', folder_id='1HC7sQ_L8nNLuYO3KGIvyTduNANAvlH6L')
# report = sa.open('aaaam4')
# wks = report.worksheet('Sheet1')
# report.share('jason.redfoot@corvidtec.com', perm_type='user', role='writer')
# wks.update('C3', 'Fill-Out')