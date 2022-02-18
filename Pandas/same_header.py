import csv
import pandas as pd

file = pd.read_csv('./Pandas/Vue_Health.csv')
file1 = open('./Pandas/Vue_Health.csv', 'r')
# matches = open('/Pandas/Vue_Healther_Header_Matches.csv', 'w')

columns = ['Source User Email', 'Sender Domain', 'Mimecast Header From', 'Count of Records']

reader = csv.DictReader(file1, fieldnames=columns)
# allowed_writer = csv.DictWriter(matches, columns)
with open('./Pandas/Vue_Health_Domain_No_Matches.csv', 'w', newline='') as matches:
    different_writer = csv.DictWriter(matches, columns)
    different_writer.writeheader()
    for row in reader:
        if row['Sender Domain'] not in row['Mimecast Header From']:
            different_writer.writerow(row)
            print(row)