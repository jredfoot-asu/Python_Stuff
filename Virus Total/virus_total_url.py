import requests
import json
import csv
import time

FILE = r"C:\Users\jredfoot\Documents\Reporting\Files\virus_total.json"
CSV_FILE = r'C:\Users\jredfoot\Documents\Reporting\Files\malware_proxy_urls.csv'
VT_OUT = r'C:\Users\jredfoot\Documents\Reporting\Files\vt_out.csv'

url = 'https://www.virustotal.com/vtapi/v2/url/report'

def csv_url_read():
    with open(CSV_FILE, 'r') as read:
        reader = csv.DictReader(read)
        with open(VT_OUT, 'w', newline='') as write:
            columns = ['Customer','Kibana ID', 'TLP', 'Hive ID', 'Threat Type', 'URL', 'VirusTotal: Total Engines', 'VirusTotal: Total Positives', 'Percent Positive']
            writer = csv.DictWriter(write, fieldnames=columns)
            writer.writeheader()
            for line in reader:
                if set(line).pop() == 0:
                    break
                else:
                    try:
                        csv_url = line['URL']

                        params = {'apikey': 'c96acc2a52f579a737bc468b46a8774401728bf278ed8636e61b1a44e72e373b', 'resource': csv_url}
                        response = requests.get(url, params)
                        vt_response = response.json()
                        percentage = vt_response.get('positives')/vt_response.get('total')
                        #print(csv_url)
                        print(vt_response.get('positives'))
                        print(vt_response.get('total'))
                        print('{:.0%}'.format(percentage))
                        line['VirusTotal: Total Engines'] = vt_response.get('total')
                        line['VirusTotal: Total Positives'] = vt_response.get('positives')
                        line["Percent Positive"] = '{:.0%}'.format(percentage)
                        vt_out_data = line
                        #print(line)
                        # print(vt_out_data)
                        writer.writerow(vt_out_data)
                        time.sleep(20)
                    except Exception as e:
                        writer.writerow(vt_out_data)
                        print(e)
                        print(response.status_code)
                        pass


    read.close()
    write.close()

response = csv_url_read()

# with open(FILE, 'w') as f:
#     json.dump(csv_url_read.json(), f, indent=4)