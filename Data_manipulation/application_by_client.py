import csv
import os

# client = input('input a client name: ')
# os.mkdir(client)
# final_csv =  'total_applications.csv'
# final_out = open(client + '/' + final_csv, 'w')
# final_writer = csv.writer(final_out)
def vmware(client, writer):
    vmware = open('./Data_manipulation/VMWare.csv', 'r')
    vreader = csv.reader(vmware)

    for r in vreader:
        if client in r[0] and r[1] != "HTTPS.BROWSER" and r[1] != 'http-proxy' and r[1] != 'ssl' and r[1] != 'vmware-carbon-black' and r[1] != 'webdav':
            vmware_info = r[1], r[2], 'VMware'
            writer.writerow(vmware_info)

def broadcom(client, writer):
    broadcoam = open('./Data_manipulation/Broadcom_client_list.csv', 'r')
    breader = csv.reader(broadcoam)

    for r in breader:
        if client in r[0]:
            broadcom_info = r[1], r[2], r[3], r[4], 'Broadcom'
            writer.writerow(broadcom_info)

def apache(client, writer):
    apache = open('./Data_manipulation/Apache List.csv', 'r')
    areader = csv.reader(apache)

    for r in areader:
        if client in r[0]:
            apache_info = r[1], r[2], r[3], r[4], 'Apache'
            writer.writerow(apache_info)

def cisco(client, writer):
    cisco = open('./Data_manipulation/Cisco Client List.csv', 'r')
    creader = csv.reader(cisco)

    for r in creader:
        if client in r[0] and r[1] != 'ssl' and r[1] != 'http-proxy' and r[1] != 'smtp-base' and r[1] != 'linkedin-base' and r[1] != 'web-browsing' and r[1] != 'HTTPS.BROWSER' and r[1] != 'owncloud-downloading':
            cisco_info = r[1], r[2], r[3], r[4], "Cisco"
            writer.writerow(cisco_info)

def ubiquiti(client, writer):
    ubiquiti = open('./Data_manipulation/Ubiquiti Client List.csv', 'r')
    ureader = csv.reader(ubiquiti)

    for r in ureader:
        if client in r[0] and r[1] != 'web-browsing':
            ubiquiti_info = r[1], r[2], r[3], r[4], 'Ubiquiti'
            writer.writerow(ubiquiti_info)

def trendmicro(client, writer):
    trendmicro = open('./Data_manipulation/TrendMicro Client List.csv', 'r')
    treader = csv.reader(trendmicro)

    for r in treader:
        if client in r[0] and r[1] != 'ssl':
            trendmicro_info = r[1], r[2], r[3], r[4], 'TrendMicro'
            writer.writerow(trendmicro_info)

def splunk(client, writer):
    splunk = open('./Data_manipulation/Splunk Client List.csv', 'r')
    splunkreader = csv.reader(splunk)

    for r in splunkreader:
        if client in r[0]:
            splunk_info = r[1], r[2], r[3], r[4], 'Splunk'
            writer.writerow(splunk_info)

def spring(client, writer):
    spring = open('./Data_manipulation/Spring Clients List.csv', 'r')
    springreader = csv.reader(spring)

    for r in springreader:
        if client in r[0] and '.jar' in r[2]:
            spring_info = r[1], r[2], r[3], r[4], 'Spring'
            writer.writerow(spring_info)

def sophos(client, writer):
    sophos = open('./Data_manipulation/Sophos Client List.csv', 'r')
    sophosreader = csv.reader(sophos)

    for r in sophosreader:
        if client in r[0] and 'sophos' not in r[2]:
            sophos_info = r[1], r[2], r[3], r[4], 'Sophos'
            writer.writerow(sophos_info)

def azure(client, writer):
    azure = open('./Data_manipulation/Microsoft Azure Client List.csv', 'r')
    azurereader = csv.reader(azure)

    for r in azurereader:
        if client in r[0] and 'azure' not in r[2]:
            azure_info = r[1], r[2], r[3], r[4], 'Azure'
            writer.writerow(azure_info)

def amazon(client, writer):
    amazon = open('./Data_manipulation/Amazon AWS.csv', 'r')
    amazonreader = csv.reader(amazon)

    for r in amazonreader:
        if client in r[0] and r[1] != 'snapchat' and 'dell' not in r[2] and 'aws.' not in r[2] and 'aws-' not in r[2]:
            amazon_info = r[1], r[2], r[3], r[4], 'Amazon'
            writer.writerow(amazon_info)

def atlassian(client, writer):
    atlassian = open('./Data_manipulation/Atlassian Client List.csv', 'r')
    atlassianreader = csv.reader(atlassian)

    for r in atlassianreader:
        if client in r[0]:
            atlassian_info = r[1], r[2], r[3], r[4], 'Atlassian'
            writer.writerow(atlassian_info)

def bmc(client, writer):
    bmc = open('./Data_manipulation/BMC Helix.csv', 'r')
    bmcreader = csv.reader(bmc)

    for r in bmcreader:
        if client in r[0]:
            bmc_info = r[1], r[2], r[3], r[4], 'BMC'
            writer.writerow(bmc_info)

def forcepoint(client, writer):
    forcepoint = open('./Data_manipulation/Forcepoint Client List.csv', 'r')
    freader = csv.reader(forcepoint)

    for r in freader:
        if client in r[0]:
            f_info = r[1], r[2], r[3], r[4], 'Forcepoint'
            writer.writerow(f_info)

def cloudera(client, writer):
    cloudera = open('./Data_manipulation/Cloudera Client List.csv', 'r')
    cloudreader = csv.reader(cloudera)

    for r in cloudreader:
        if client in r[0]:
            cloud_info = r[1], r[2], r[3], r[4], 'Cloudera'
            writer.writerow(cloud_info)

def dynatrace(client, writer):
    dynatrace = open('./Data_manipulation/Cloudera Client List.csv', 'r')
    dreader = csv.reader(dynatrace)

    for r in dreader:
        if client in r[0]:
            d_info = r[1], r[2], r[3], r[4], 'Dynatrace'
            writer.writerow(d_info)

def main():
    client = input('input a client name: ')
    os.mkdir(client)
    final_csv =  'total_applications.csv'
    final_out = open(client + '/' + final_csv, 'w')
    final_writer = csv.writer(final_out)
    vmware(client, final_writer)
    broadcom(client, final_writer)
    apache(client, final_writer)
    cisco(client, final_writer)
    ubiquiti(client, final_writer)
    trendmicro(client, final_writer)
    splunk(client, final_writer)
    spring(client, final_writer)
    sophos(client, final_writer)
    azure(client, final_writer)
    amazon(client, final_writer)
    atlassian(client, final_writer)
    bmc(client, final_writer)
    forcepoint(client, final_writer)
    cloudera(client, final_writer)
    dynatrace(client, final_writer)


if __name__ == "__main__":
    main()