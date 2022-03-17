'''Setup Constants'''

from datetime import datetime, timedelta

DETECTION_CATEGORIES = [
    'COMMAND & CONTROL',
    'RECONNAISSANCE',
    'LATERAL MOVEMENT',
    'BOTNET ACTIVITY',
    'EXFILTRATION'
    ]

# The max number of rows in certain tables
LIST_SIZE = 50

PAGE_SIZE = 500

CURRENT_DATE = datetime.now()
ONE_MONTH_AGO = CURRENT_DATE - timedelta(days=31)
THREE_MONTHS_AGO = CURRENT_DATE - timedelta(days=91)
SIX_MONTHS_AGO = CURRENT_DATE - timedelta(days=183)
