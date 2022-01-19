import requests
import json
import re
import csv
import datetime

date_time_str = '1969-12-31 12:01:01.00000'

date_time_obj = datetime.datetime.strptime(date_time_str, '%Y-%m-%d %H:%M:%S.%f').now()

FILE = r"C:\Users\jredfoot\Documents\Reporting\Files\abuse.json"
CSV_FILE = r"C:\Users\jredfoot\Documents\Reporting\malware_virus_total-2020-10-01.csv"

# Defining the api-endpoint
url = 'https://api.abuseipdb.com/api/v2/check'

def abuse_IPDB():
    with open(CSV_FILE, 'r') as read:
        reader = csv.DictReader(read)
        with open('abuse_ipdb.csv', 'w', newline='') as write:
            columns = ['Customer','Kibana ID', 'TLP', 'Hive ID', 'Threat Type', 'URL', 'Destination IP', 'Abuse IPDB Score', 'VirusTotal: Total Engines', 'VirusTotal: Total Positives', 'Percent Positive']
            writer = csv.DictWriter(write, fieldnames=columns)
            writer.writeheader()
            for line in reader:
                if set(line).pop() == 0:
                    break
                else:
                    try:
                        ip_address = line['Destination IP']
                        querystring = {
                        'ipAddress': ip_address,
                        'maxAgeInDays': '365'
                        }
                        headers = {
                        'Accept': 'application/json',
                        'Key': '105234e7f5009b4b0d8b8647b2023cbc15452cdf006d0b378ec3e8fba1c7ecc8e7f842c8612caf12'
                        }
                        decodedResponse = response.json()
                        json.dump(decodedResponse, f, indent=4)
                        # score = decodedResponse['data']['abuseConfidenceScore']
                        line['Abuse IPDB Score'] = decodedResponse['data']['abuseConfidenceScore']
                        abuse_IPDB_out = line
                        writer.writerow(abuse_IPDB_out)
                    except Exception as e:
                        writer.writerow(abuse_IPDB_out)
                        print(e)
                        print(response.status_code)
                        pass

def main():
    abuse_IPDB

if __name__ == "__main__":
    main()