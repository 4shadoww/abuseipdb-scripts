#!/usr/bin/env bash

if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters" >&2
    echo "usage: $0 <api-key>"
    exit 1
fi

today=`date -d '-1 day' +%Y-%m-%d`
today_no_year=`date -d '-1 day' +%m-%d`

# Parse access log
python parse_access_logs.py /var/log/nginx/access.log -o access.csv -d $today

if [[ $? = 0 && `wc -l<access.csv` -ge 2  ]]; then
    python send-bulk.py $1 access.csv
fi

# Parse auth log
python parse_auth_logs.py /var/log/auth.log -o auth.csv -d $today

if [[ $? = 0 && `wc -l<auth.csv` -ge 2 ]]; then
    python send-bulk.py $1 auth.csv
fi

# Check ip scans
lpsd -i /var/log/kern.log.1,/var/log/kern.log -t 60 -s 2 -csv -o portscans.csv -d $today_no_year

if [[ $? = 0 ]]; then
    python parse_portscan_logs.py portscans.csv -o scans.csv
    if [[ $? = 0 && `wc -l<scans.csv` -ge 2 ]]; then
        python send-bulk.py $1 scans.csv
    fi
fi
