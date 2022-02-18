import csv
import pandas as pd

with open('./Elastic_API/aaaam4_URLs.csv', 'r') as f:
    reader = csv.reader(f)
    for row in reader:
        text = row[2]
    # print(text)

df = pd.read_csv('./Elastic_API/aaaam4_Blocked_URLs.csv')
print(df.iloc[0, 0])