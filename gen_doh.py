import argparse
import csv
import subprocess

parser = argparse.ArgumentParser(description="Generate DNS over HTTPS traffic using doh-client")
parser.add_argument('csvfile', metavar='csvfile', default="majestic_million.csv", help="CSV file of domains, default to majestic_million.csv")
parser.add_argument('--post', dest="post", action="store_true", default=False, help="Use HTTP POST instead of GET")
args = parser.parse_args()

with open(args.csvfile, newline='') as csvfile:
    urlreader = csv.reader(csvfile, delimiter=',')
    count = 0
    for row in urlreader:
        if count == 100000:
            exit()
        domain = row[2]
        if args.post:
            subprocess.Popen(['doh-client', '--cafile', 'selfsigned.pem', '--domain', 'doh-server', '--qname', domain, '--post'])
        else:
            subprocess.Popen(['doh-client', '--cafile', 'selfsigned.pem', '--domain', 'doh-server', '--qname', domain])
        count += 1
