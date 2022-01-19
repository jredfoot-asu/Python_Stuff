#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import sys
import csv

import magic
import os
import warnings
import json
import requests
import re
import time


from thehive4py.api import TheHiveApi
from thehive4py.auth import BasicAuth, BearerAuth
from thehive4py.models import CaseHelper
from thehive4py.query import Parent, Id, And, Eq
from thehive4py.exceptions import TheHiveException, CaseException, CaseTaskException, CaseTemplateException, AlertException, CaseObservableException, CustomFieldException

url_value = input("Please enter your Hive URL: ")
key_value = input("Please enter your Hive key: ")
api = TheHiveApi(url_value, key_value)


def mark_alert_as_read(file):
    with open(file, 'r') as read:
        reader = csv.DictReader(read)
        for line in reader:
            line = line['Hive ID']
            alert_id = line
            response = api.mark_alert_as_read(alert_id)
#close the file so that if the program needs to be run again, the file is writable.
    read.close()

def main():
    vt_file = input('Please input the file path or file name you would like to mark alerts as read:')
    mark_alert_as_read(file=vt_file + '.csv')


if __name__ == "__main__":
    main()