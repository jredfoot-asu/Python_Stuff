import csv

myDict = {}

input_file = csv.DictReader(open('/Users/jredfoot/Desktop/Practice_Python/Data_manipulation/Total CylancePROTECT Events and Their Count.csv'))

#for row in input_file:
    #print(row)
devices = []
with open('/Users/jredfoot/Desktop/Practice_Python/Data_manipulation/Total CylancePROTECT Events and Their Count.csv', 'r') as f:
    reader = csv.reader(f)
    headers = next(reader)[1:]
    for row in reader:
        myDict[row[0]] = {key: str(value) for key, value in zip(headers, row[1:])}
        # print(row)
        if row[1] not in devices:
            devices.append(row[1])
        threats = {}
        for device in devices:
            if 'Threat' in row[0]:
                threats[device] = row[2]
                #print(row[1], row[2])
            elif 'Threat' not in row[0]: 
                    threats[device] = 0
        print(threats)
#print(devices)
    
    # dict_from_csv = {row[0]: {row[1]: row[2]} for row in reader}
