from datetime import datetime

currentMonth = datetime.now().month
currentYear = datetime.now().year
# print(currentMonth, currentYear)
report_month = 0
report_year = 0

if currentMonth == 1:
    report_month = 12
    report_year = currentYear -1
else:
    report_month = currentMonth - 1
    report_year = currentYear

print(report_month, report_year)