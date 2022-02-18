import csv
import pprint


# cabarrus = open('/Users/jredfoot/Desktop/Practice_Python/Data_manipulation/Cabarrus_County_Devices.csv', 'r')
# vmware = open('/Users/jredfoot/Desktop/Practice_Python/Data_manipulation/VMWare.csv', 'r')
# with open('/Users/jredfoot/Desktop/Practice_Python/Data_manipulation/Cabarrus_County_Devices.csv', 'r') as c:
#     creader = csv.reader(c)
#     for row in creader:
# c.close

ipAddress = []
def organizationIP():
    with open('/Users/jredfoot/Desktop/Practice_Python/Data_manipulation/VMWare.csv', 'r') as v:
        vreader = csv.reader(v)
        for row in vreader:
            if 'Cabarrus County' in row[0]:
                ipAddress.append(row[2])



            #print(ipAddress)
# dict_list = {}
def deviceInfo():
    with open('/Users/jredfoot/Desktop/Practice_Python/Data_manipulation/Cabarrus_County_Devices.csv', 'r') as c:
        creader = csv.DictReader(c, fieldnames=('Name', 'IP Address', 'Last Reported User'))
        # headers = next(creader)
        with open('Cylance.csv', 'w') as f, open("NoCylance.csv", 'w') as g:
            writer1 = csv.writer(f)
            writer2 = csv.writer(g)
            for row in creader:
                dict_list = {}
                # print(row)
                dict_list.update(row)
            
                # with open('Cylance.txt', 'w') as f:
                for i in ipAddress:
                    if i == dict_list['IP Address']:
                        # print(dict_list["Name"], dict_list['IP Address'])
                        device_info = dict_list['Name'], dict_list['IP Address']
                        writer1.writerow(device_info)
                    elif i != dict_list['IP Address']:
                        no_info = 'N/A', i
                        writer2.writerow(no_info)
                        


    

def main():
    deviceInfo()
    organizationIP()
    device = deviceInfo()
    #print(ipAddress)
    print(deviceInfo())
    
    # counter = 0
    # for i in ipAddress:
    #     #print(i)
    #     # print(device[counter][1])
    #     # counter = counter + 1
        
    # if i in ipAddress and i in device[counter][1]:
    #     print(device[counter][0])
    #     counter = counter + 1
    #     #     print(device[])



if __name__ == "__main__":
    main()