#!/usr/bin/env python3

import os
import sys
import argparse
import re
import csv
from datetime import datetime, timezone
import pytz

regex_patterns = [
    r"wp-login\.php",
    r"^\/database",
    r"^\/backups?"
    r"^\/te?mp\/",
    r"^\/boaform\/",
    r"^\/admin\/",
    r"^\/\.git\/config",
    r"^\/HNAP1\/",
    r"^\/showLogin\.cc",
    r"^MGLNDD_([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})_443",
    r"^\/ads\.txt",
    r"^\/[_2]?phpmy-?admin",
    r"^\/pma",
    r"^\/phpmy",
    r"^\/dbadmin",
    r"^\/sql",
    r"^\/db",
    r"^\/mysql",
    r"^\/shopdb",
    r"^\/admin",
    r"^\/program",
    r"^\/phppma",
    r"^\/administrator",
    r"^\/wp-content",
    r"^\/\.bash_history",
    r"^\/\.ssh\/id_rsa",
    r"^\/\.htpasswd~?",
    r"^\/dump",
    r"^\/[^\/]+?\.sql",
    r"^\/setup\.cgi",
    r"^\/[^\/]+?\.zip",
    r"^\/[^\/]+?\.7z",
    r"^\/[^\/]+?\.tar\.gz",
    r"^\/owa\/",
    r"^\/ecp\/",
    r"^\\\\x.{2}\\\\x.{2}",
    r"^\/0bef",
    r"^\/private",
    r"^\/secret",
    r"^\/app\/",
    r"admin\.php",
    r"^\/vendor\/phpunit",
    r"^\?.*?=",
    r"adminer\.php"
    r"^\/solr",
    r"^\/spog",
    r"^\/cgi-bin",
    r"^\/index\.php",
    r"^https?:",
    r"^\/dispatch\.asp",
    r"wp-includes",
    r"^\/wordpress",
    r"^\/website",
    r"system_api\.php",
    r"clients_live\.php",
    r"live\.php",
    r"^\/console",
    r"phpinfo",
    r"editBlackAndWhiteList",
    r"^\/.env",
    r"^\/acme_challenge",
    r"^\/app",
    r"^\/audio",
    r"^\/backup",
    r"^\/api",
    r"^\/client",
    r"^\/prod",
    r"^\/shell",
    r"^\/src",
    r"^\/source",
    r"^\/.*?\.php",
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
        ipv4 = r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
        timestamp = r"([0-9]{1,2}\/[A-Za-z]{1,3}\/[0-9]{1,4}:[0-9]{2}:[0-9]{2}:[0-9]{2})"
        comment = r"(\"(GET|POST|PUT|DELETE|HEAD|CONNECT|TRACE|PATCH|OPTIONS) (.*?) HTTP\/[0-9]{1,3}\.[0-9]{1,3}\")"

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
