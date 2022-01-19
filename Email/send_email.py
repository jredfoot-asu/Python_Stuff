import smtplib, ssl

smtp_server = 'smtp.gmail.com'
port = 465

sender_email = 'jredfootrocus@gmail.com'
password = 'F@natic1021'

context = ssl.create_default_context()

receiever_email = 'j.redfoot@outlook.com'
message = '''\
    Subject: Hi There! Testing 123!

    This message is sent from Python.'''

context = ssl.create_default_context()

with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
    server.login(sender_email, password)
    server.sendmail(sender_email, receiever_email, message)