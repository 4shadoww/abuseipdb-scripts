#!/usr/bin/env python3

import sys
import os
import requests
import json

def print_help():
    print("usage: " + sys.argv[0] + " <api-key> <file>")

def main():
    if len(sys.argv) < 3:
        print_help()
        sys.exit(1)

    if not os.path.exists(sys.argv[2]):
        print("file doesn't exist")
        sys.exit(1)

    url = 'https://api.abuseipdb.com/api/v2/bulk-report'

    files = {
        'csv': (os.path.basename(sys.argv[2]), open(sys.argv[2], 'rb'))
    }

    headers = {
        'Accept': 'application/json',
        'Key': sys.argv[1]
    }

    response = requests.request(method='POST', url=url, headers=headers, files=files)

    # Formated output
    decoded_response = json.loads(response.text)
    print(json.dumps(decoded_response, sort_keys=True, indent=4))

if __name__ == '__main__':
    main()
