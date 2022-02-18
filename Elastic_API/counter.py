from collections import Counter, defaultdict
import csv
import pandas as pd

# count = 0
# def counter():
#     with open('./Elastic_API/Goalsetter_URLs.csv', 'r', newline='') as f, open('./Elastic_API/Goalsetter_Count_URLs.csv', 'w', newline='') as d:
#         # c = Counter(f)
#         # dups = [t for t in c.most_common() if t[1] > 1]
#         # dups_dict = {row: count for row, count in c.most_common() if count > 1}
#         #print(c.most_common())
#         # new_file = {}
#         # for item in c.most_common():
#         #     new_file.update(item)
#         #     print(new_file)


#         reader = csv.DictReader(f)
#         new_dict = {'user_name': '', 'url_original': '', 'source_ip': '', 'destination_ip': '', 'count': ''}
#         count = 0
#         columns = ['user_name', 'url_original', 'source_ip', 'destination_ip', 'count']
#         writer = csv.DictWriter(d, fieldnames=columns)
#         writer.writeheader()
#         for row in reader:
#             if row['user_name'] == new_dict['user_name'] and row['url_original'] == new_dict['url_original'] and row['source_ip'] == new_dict['source_ip'] and row['destination_ip'] == new_dict['destination_ip']:
#                 increase_count = new_dict['count'] + 1
#                 total_count = {'count': increase_count}
#                 new_dict.update(total_count)
#             else:
#                 user_name = {'user_name': row['user_name']}
#                 url = {'url_original': row['url_original']}
#                 source_ip = {'source_ip': row['source_ip']}
#                 destination_ip = {'destination_ip': row['destination_ip']}
#                 new_dict.update(user_name)
#                 new_dict.update(url)
#                 new_dict.update(source_ip)
#                 new_dict.update(destination_ip)
#                 count = count + 1
#                 total_count = {'count': count}
#                 new_dict.update(total_count)

#         # print(new_dict)
#             # if:
#             #     increase_count = new_dict['count'] + 1
#             #     total_count = {'count': increase_count}
#             #     new_dict.update(total_count)
#             writer.writerow(new_dict)

#         # print(new_dict)

# counter()


# new_dict = {}
# with open('./Elastic_API/Goalsetter_URLs.csv', 'r', newline='') as f, open('./Elastic_API/Goalsetter_Count_URLs.csv', 'w', newline='') as d:
#     new_dict = {}
#     # c = Counter(f)
#     # dups = [t for t in c.most_common() if t[1] > 1]
#     # dups_dict = {row: count for row, count in c.most_common() if count > 1}
#     #print(c.most_common())
#     # new_file = {}
#     # for item in c.most_common():
#     #     new_file.update(item)
#     #     print(new_file)

#     f_user = []
#     f_url = []
#     f_source = []
#     f_destination = []
#     reader = csv.DictReader(f)
    
#     count = 0
#     columns = ['user_name', 'url_original', 'source_ip', 'destination_ip', 'count']
#     writer = csv.DictWriter(d, fieldnames=columns)
#     writer.writeheader()
#     for row in reader:
#         user_name = {'user_name': row.get('user_name')}
#         url = {'url_orginal': row.get('url_original')}
#         source_ip = {'source_ip': row.get('source_ip')}
#         destination_ip = {'destination_ip': row.get('destination_ip')}
#         count = {'count': count}
#         if row.get('user_name') in f_user:
            
#             if row.get('url_original') in f_url:
                
#                 if row.get('source_ip') in f_source:
#                     if row.get('destination_ip') in f_destination:
                        
#                         continue
#                     else:
#                         f_user.append(row.get('user_name'))
#                         f_url.append(row.get('url_original'))
#                         f_source.append(row.get('source_ip'))
#                         f_destination.append(row.get('destination_ip'))


#                         new_dict.update(user_name)
#                         new_dict.update(url)
#                         new_dict.update(source_ip)
#                         new_dict.update(destination_ip)
#                         new_dict.update(count)

#                         print(new_dict) 


in_file = pd.read_csv('./Elastic_API/Goalsetter_URLs.csv')
# decending_sort = in_file.sort_values(by=['user_name', 'url_original'], ignore_index=True, ascending=False)
updated = in_file.groupby(in_file.columns.tolist()).size().reset_index().rename(columns={0: 'count'})
updated1 = updated.sort_values(by=['count'], ascending=False)
updated1.to_csv('./Elastic_API/Goalsetter_Count_URLs2.csv')
print(updated)
duplicates= in_file.drop_duplicates(keep='first', subset=['user_name', 'url_original'])
duplicates.to_csv('./Elastic_API/Goalsetter_Count_URLs.csv')