#!/usr/bin/env bash

if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters" >&2
    echo "usage: $0 <api-key>"
    exit 1
fi

today=`date +%Y-%m-%d`

# Parse access log
python parse_access_logs.py /var/log/nginx/access.log -o access.csv -d $today

if [[ $? = 0 && `wc -l<access.csv` -ge 2  ]]; then
    python send-bulk.py $1 access.csv
fi

# Parse auth log
python parse_auth_logs.py /var/log/auth.log -o auth.csv -d $today

if [[ $?  = 0 && `wc -l<auth.csv` -ge 2 ]]; then
    python send-bulk.py $1 auth.csv
fi
