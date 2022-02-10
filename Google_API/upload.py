import gspread

sa = gspread.service_account(filename='./Elastic_API/client_secret.json')
sh = sa.create('aaaam4_Cylance_Device_Control')
with open('./Elastic_API/aaaam4_Cylance_Device_Control.csv') as f:
    content = f.read()
    sa.import_csv(sh.id, data=content)
    sh.share('jason.redfoot@corvidtec.com', perm_type='user', role='writer')