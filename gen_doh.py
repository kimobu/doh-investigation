import argparse
import csv
import subprocess

parser = argparse.ArgumentParser(description="Generate DNS over HTTPS traffic using doh-client")
parser.add_argument("csvfile", metavar="csvfile", default="majestic_million.csv", help="CSV file of domains, default to majestic_million.csv")
parser.add_argument("--post", dest="post", action="store_true", default=False, help="Use HTTP POST instead of GET")
parser.add_argument("--count", dest="count", default="10000", help="Count of DoH packets to generate")
args = parser.parse_args()

with open(args.csvfile, newline='') as csvfile:
    urlreader = csv.reader(csvfile, delimiter=',')
    counter = 0
    for row in urlreader:
        if counter == args.count:
            exit()
        domain = row[2]
        if args.post:
            subprocess.Popen(['doh-client', '--cafile', 'selfsigned.pem', '--domain', 'doh-server', '--qname', domain, '--post'])
        else:
            subprocess.Popen(['doh-client', '--cafile', 'selfsigned.pem', '--domain', 'doh-server', '--qname', domain])
        counter += 1
