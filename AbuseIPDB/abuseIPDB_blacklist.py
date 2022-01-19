import requests
import json

# Defining the api-endpoint
url = 'https://api.abuseipdb.com/api/v2/blacklist'

querystring = {
    'confidenceMinimum':'100'
}

headers = {
    'Accept': 'application/json',
    'Key': '105234e7f5009b4b0d8b8647b2023cbc15452cdf006d0b378ec3e8fba1c7ecc8e7f842c8612caf12'
}

response = requests.request(method='GET', url=url, headers=headers, params=querystring)

# Formatted output
decodedResponse = json.loads(response.text)
print(json.dumps(decodedResponse, sort_keys=True, indent=4))
