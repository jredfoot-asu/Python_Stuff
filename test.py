from elasticsearch import Elasticsearch
import json
import csv

# Connect to the elastic instance.
client = Elasticsearch(
    "https://lb-es.rocusnetworks.local:9200",
    verify_certs=False,
    api_key=("hjaqT34BIH6T_vw3S4tj", "ixuZn8myQfCjJlEIciVB3g"),
    timeout=60,
    max_docs=10000,
)

firewall_query = {
	"query": {
	"bool": {
		"must": 
        [],
			'filter': [
				{'range': {'@timestamp': {'gte': '2021-11-02T05:00:00.000Z', 'lte': '2021-12-01T05:00:00.000Z', "format": "strict_date_optional_time"}}},
                {'match_phrase': {"organization.id": 'aaaam4'}},
                {'match_phrase': {'event.action': 'url_filtering'}},
                {'match_phrase': {'observer.type': 'firewall'}},
				]
				}
			}
		}

cylance_query = {
    "query": {
        "bool": {
            "must": [],
                "filter": [
                    {'range': {'@timestamp': {'gte': '2021-11-02T05:00:00.000Z', 'lte': '2021-12-01T05:00:00.000Z', "format": "strict_date_optional_time"}}},
                    {'match_phrase': {"organization.id": 'aaaam4'}},
                    {'match_phrase': {'event.module': 'CylancePROTECT'}},
                ]
        }
    }
}

mimecast_query = {
    "query": {
        "bool": {
            "must": [],
                "filter": [
                    {'range': {'@timestamp': {'gte': '2021-11-02T05:00:00.000Z', 'lte': '2021-12-01T05:00:00.000Z', "format": "strict_date_optional_time"}}},
                    {'match_phrase': {"organization.id": 'aaaam4'}},
                    {'match_phrase': {'event.module': 'mimecast'}},
                ]
        }
    }
}

resp = client.search(index='haven*', body=mimecast_query, size=10000)
count = resp['hits']['total']['value']
# print(count)
for hit in resp['hits']['hits']:
    print(hit['_source']['mimecast']['sender']['domain'])


# url filtering function. Creates a spreadsheet with all the url filtering information on it.
def url_filtering (firewall):
    resp = client.search(index='haven*', body=firewall, size=10000)
    with open('./Elastic_API/Goalsetter_URLs.csv', 'w', newline='') as f:
        alert_list = {}
        columns = ['user_name', 'event_outcome', 'url_original', 'source_ip', 'destination_ip']
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        count = resp['hits']['total']['value']
        for hit in resp['hits']['hits']:
            user_name = {'user_name': hit['_source']['client']['user']['name']}
            event_outcome = {'event_outcome': hit['_source']['event']['outcome']}
            url_original = {'url_original': hit['_source']['url']['original']}
            destination_ip = {'destination_ip': hit['_source']['destination']['ip']}
            source_ip = {'source_ip': hit['_source']['source']['ip']}

            alert_list.update(user_name)
            alert_list.update(event_outcome)
            alert_list.update(url_original)
            alert_list.update(source_ip)
            alert_list.update(destination_ip)
            writer.writerow(alert_list)

        return
    f.close()

# Cylance function for threats.
def cylance_threats(cylance):
    resp = client.search(index='haven*', body=cylance, size=10000)
    with open('./Elastic_API/Goalsetter_Cylance_Threats.csv', 'w', newline='') as f:
        alert_list = {}
        columns = ['device_name', 'event_type', 'event_action', 'file_path', 'file_name']
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for hit in resp['hits']['hits']:
            event_type = hit['_source']['cylance']['event']['type']
            if event_type == 'Threat':
                device_name = {'device_name': hit['_source']['observer']['name']}
                event = {'event_type': event_type}
                event_action = {'event_action': hit['_source']['event']['action']}
                file_path = {'file_path': hit['_source']['file']['path']}
                file_name = {'file_name': hit['_source']['file']['name']}

                alert_list.update(device_name)
                alert_list.update(event)
                alert_list.update(event_action)
                alert_list.update(file_path)
                alert_list.update(file_name)

                writer.writerow(alert_list)
        return
    f.close()

def cylance_exploits(cylance):
    resp = client.search(index='haven*', body=cylance, size=10000)
    with open('./Elastic_API/Goalsetter_Cylance_Exploits.csv', 'w', newline='') as f:
        alert_list = {}
        columns = ['device_name', 'event_type', 'process_name', 'violation_type', 'event_action']
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for hit in resp['hits']['hits']:
            event_type = hit['_source']['cylance']['event']['type']
            if event_type == 'ExploitAttempt':
                device_name = {'device_name': hit['_source']['observer']['name']}
                event = {'event_type': hit['_source']['cylance']['event']['type']}
                process_name = {'process_name': hit['_source']['process']['name']}
                violation_type =  {'violation_type': hit['_source']['cylance']['violation_type']}
                event_action = {'event_action': hit['_source']['event']['action']}

                alert_list.update(device_name)
                alert_list.update(event)
                alert_list.update(process_name)
                alert_list.update(violation_type)
                alert_list.update(event_action)

                writer.writerow(alert_list)
        return
    f.close()

def cylance_scripts(cylance):
    resp = client.search(index='haven*', body=cylance, size=10000)
    with open('./Elastic_API/Goalsetter_Cylance_Scripts.csv', 'w', newline='') as f:
        alert_list = {}
        columns = ['device_name', 'file_path', 'file_hash', 'type_of_script', 'event_action']
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for hit in resp['hits']['hits']:
            event_type = hit['_source']['cylance']['event']['type']
            if event_type == 'ScriptControl':
                device_name = {'device_name': hit['_source']['observer']['name']}
                file_path = {'file_path': hit['_source']['file']['path']}
                file_hash = {'file_hash': hit['_source']['file']['hash']['sha256']}
                type_of_script = {'type_of_script': hit['_source']['cylance']['interpreter']}
                event_action = {'event_action': hit['_source']['cylance']['event']['name']}

                alert_list.update(device_name)
                alert_list.update(file_path)
                alert_list.update(file_hash)
                alert_list.update(type_of_script)
                alert_list.update(event_action)

                writer.writerow(alert_list)
        return
    f.close()

def cylance_deviceControl(cylance):
    resp = client.search(index='haven*', body=cylance, size=10000)
    with open('./Elastic_API/Goalsetter_Cylance_Device_Control.csv', 'w', newline='') as f:
        alert_list = {}
        columns = ['device_name', 'usb_device_name']
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for hit in resp['hits']['hits']:
            event_type = hit['_source']['cylance']['event']['type']
            if event_type == 'DeviceControl':
                device_name = {'device_name': hit['_source']['observer']['name']}
                usb_device_name = {'usb_device_name': hit['_source']['cylance']['device']['name']}

                alert_list.update(device_name)
                alert_list.update(usb_device_name)

                writer.writerow(alert_list)
        return
    f.close()

deviceControl_count = 0
exploitAttempt_count = 0
scriptControl_count = 0
threats_count = 0

def cylance_totals(cylance):
    resp = client.search(index='haven*', body=cylance, size=10000)
    with open('./Elastic_API/Goalsetter_Cylance_totals.csv', 'w', newline='') as f:
        alert_list = {}
        columns = ['threats', 'exploit_attempt', 'script_control', 'device_control']
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        deviceControl_count = 0
        exploitAttempt_count = 0
        scriptControl_count = 0
        threats_count = 0
        for hit in resp['hits']['hits']:
            event_type = hit['_source']['cylance']['event']['type']
            if event_type == 'DeviceControl':
                deviceControl_count = deviceControl_count + 1
            if event_type == 'ScriptControl':
                scriptControl_count = scriptControl_count + 1
            if event_type == 'ExploitAttempt':
                exploitAttempt_count = exploitAttempt_count +1
            if event_type == 'Threat':
                threats_count = threats_count + 1
        deviceControl = {'device_control': deviceControl_count}
        exploitAttempt = {'exploit_attempt': exploitAttempt_count}
        scriptControl = {'script_control': scriptControl_count}
        threats = {'threats': threats_count}

        alert_list.update(threats)
        alert_list.update(exploitAttempt)
        alert_list.update(scriptControl)
        alert_list.update(deviceControl)
        writer.writerow(alert_list)
    f.close()

def mimecast(mimecast):
    resp = client.search(index='haven*', body=mimecast, size=10000)
    with open('./Elastic_API/Goalsetter_Mimecast.csv', 'w', newline='') as f:
        alert_list = {}
        columns = ['threats', 'exploit_attempt', 'script_control', 'device_control']
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        # for hit in resp['hits']['hits']:





# cylance_totals(cylance_query)

