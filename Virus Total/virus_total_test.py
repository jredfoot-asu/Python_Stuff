import requests
import json

FILE = r"C:\Users\jredfoot\Documents\Reporting\Files\virus_total.json"

url = 'https://www.virustotal.com/vtapi/v2/url/report'

params = {'apikey': 'c96acc2a52f579a737bc468b46a8774401728bf278ed8636e61b1a44e72e373b', 'resource':'measurementwear.com/wp-content/themes/oceanwp/fantastico/'}

response = requests.get(url, params=params)

#print(response.json())

vt_response = response.json()

percentage = vt_response.get('positives')/vt_response.get('total')

print('{:.0%}'.format(percentage))

with open(FILE, 'w') as f:
    json.dump(vt_response, f, indent=4)
    