#!/usr/bin/env python3

import os
import sys
import argparse
import re
import csv
from datetime import datetime, timezone
import pytz

regex_patterns = [
    "wp-login\.php",
    "^\/database",
    "^\/backups?"
    "^\/te?mp\/",
    "^\/boaform\/",
    "^\/admin\/",
    "^\/\.git\/config",
    "^\/HNAP1\/",
    "^\/showLogin\.cc",
    "^MGLNDD_([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})_443",
    "^\/ads\.txt",
    "^\/[_2]?phpmy-?admin",
    "^\/pma",
    "^\/phpmy",
    "^\/dbadmin",
    "^\/sql",
    "^\/db",
    "^\/mysql",
    "^\/shopdb",
    "^\/admin",
    "^\/program",
    "^\/phppma",
    "^\/administrator",
    "^\/wp-content",
    "^\/\.bash_history",
    "^\/\.ssh\/id_rsa",
    "^\/\.htpasswd~?",
    "^\/dump",
    "^\/[^\/]+?\.sql",
    "^\/setup\.cgi",
    "^\/[^\/]+?\.zip",
    "^\/[^\/]+?\.7z",
    "^\/[^\/]+?\.tar\.gz",
    "^\/owa\/",
    "^\/ecp\/",
    "^\\\\x.{2}\\\\x.{2}",
    "^\/0bef",
    "^\/private",
    "^\/secret",
    "^\/app\/",
    "admin\.php",
    "^\/vendor\/phpunit",
    "^\?.*?=",
    "adminer\.php"
    "^\/solr",
    "^\/spog",
    "^\/cgi-bin",
    "^\/index\.php",
    "^https?:",
    "^\/dispatch\.asp",
    "wp-includes",
    "^\/wordpress",
    "^\/website",
    "system_api\.php",
    "clients_live\.php",
    "live\.php",
    "^\/console",
    "phpinfo",
    "editBlackAndWhiteList"
]

def malicious_request(path):
    for pattern in regex_patterns:
        result = re.match(pattern, path, re.IGNORECASE)
        if result: return True

    return False

def parse_date(s):
    c = s.count('-')
    result = None

    try:
        if c == 2:
            result = datetime.strptime(s, "%Y-%m-%d")
        elif c == 1:
            result = datetime.strptime(s, "%Y-%m")
        elif c == 0:
            result = datetime.strptime(s, "%Y")
    except ValueError:
        print("invalid date\nformat: %Y-%m-%d")

    return (result, c)

def dates_equal(d1, d2, dtype):
    if dtype == 2 and d1.date() == d2.date(): return True
    elif dtype == 1 and d1.month == d2.month and d1.year == d2.year: return True
    elif dtype == 0 and d1.year == d2.year: return True

    return False


def main(arguments):
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('infile', help="Input file", type=argparse.FileType('r'))
    parser.add_argument('-o', '--outfile', help="Output file",
                        default=sys.stdout, type=argparse.FileType('w'))
    parser.add_argument('-d', '--date', default=False, help="Date to check")

    args = parser.parse_args(arguments)

    dtype = None
    date = None

    if args.date:
        date, dtype = parse_date(args.date)
        if date == None: sys.exit(1)

    # Define field names.
    fieldnames = ['IP', 'Categories', 'Comment', 'ReportDate']
    # Begin CSV output.
    writer = csv.DictWriter(args.outfile, fieldnames=fieldnames)
    writer.writeheader()

     # Initialize empty list to hold addresses
    ipv4_addresses = list()

    for line in args.infile:
        # !! Match this format to your system's format.
        ipv4 = "([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
        timestamp = "([0-9]{1,2}\/[A-Za-z]{1,3}\/[0-9]{1,4}:[0-9]{2}:[0-9]{2}:[0-9]{2})"
        comment = "(\"(GET|POST|PUT|DELETE|HEAD|CONNECT|TRACE|PATCH|OPTIONS) (.*?) HTTP\/[0-9]{1,3}\.[0-9]{1,3}\")"

        # The regex of the line we're looking for, built up from component regexps.
        combined_re = ipv4 + ".*?" + timestamp + ".*?" + comment

        # Run the regexp.
        matches = re.findall(combined_re, line)
        # If this line is in the format we're looking for,
        if matches:
            # Pull the tuple out of the list.
            matches_flat = matches[0]

            attack_datetime = datetime.strptime(matches_flat[1], '%d/%b/%Y:%H:%M:%S')
            if dtype and not dates_equal(date, attack_datetime, dtype): continue

            # Remove duplicate addresses from the report.
            if matches_flat[0] not in ipv4_addresses:
                ipv4_addresses.append(matches_flat[0])
            else:
                continue

            if not malicious_request(matches_flat[4]):
                continue

            # !! Set tzinfo to your system timezone using timezone.
            my_tz = pytz.timezone('Europe/Helsinki')
            attack_datetime = attack_datetime.replace(tzinfo=my_tz)

            # Format to ISO 8601 to make it universal and portable.
            attack_datetime_iso = attack_datetime.isoformat()

            # We'll add the categories column statically at this step.
            # Output as a CSV row.
            writer.writerow({
                'IP': matches_flat[0],
                'Categories': "21",
                'Comment': "Probing " + matches_flat[2],
                'ReportDate': attack_datetime_iso
            })

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
