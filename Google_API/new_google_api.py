import gspread

sa = gspread.service_account(filename='./Elastic_API/client_secret.json')
sh = sa.open('Master Copy - Data Gathering')

# wks =sh.worksheet('Sheet1')

# print('Rows ', wks.row_count)
# print('Cols ', wks.row_count)

# print(wks.acell('A9').value)
# print(wks.cell(3, 3).value)
# print(wks.get('A7:E9'))
# print(wks.get_all_records())

# wks.update('C3', 'Fill-Out')
# wks.update('D4', '=UPPER(C4)', raw=False)

# wks.delete_rows(75)

# report = sa.create('aaaam4')
# report.share('jason.redfoot@corvidtec.com', perm_type='user', role='writer')
# copy = wks.get_all_records()
# report = sa.open('aaaam4')
# aaaam4 = report.worksheet('Sheet1')
# aaaam4.update('A1:I71', copy)
# sa.del_spreadsheet('aaaam4')

sa.copy('1OgAs8jG-6bBqE3LoN4ojaCX0B1SyecrtAcRd4LeSliY', title='aaaam4', copy_permissions=True, folder_id='1CkOwPmUeb6VdiqZScCu45SP_QBXN1Z1w')
report = sa.open('aaaam4')
wks = report.worksheet('Sheet1')
# report.share('jason.redfoot@corvidtec.com', perm_type='user', role='writer')
# wks.update('C3', 'Fill-Out')