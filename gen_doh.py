import argparse
import csv
import subprocess

parser = argparse.ArgumentParser(description="Generate DNS over HTTPS traffic using doh-client")
parser.add_argument("csvfile", metavar="csvfile", default="majestic_million.csv", help="CSV file of domains, default to majestic_million.csv")
parser.add_argument("--post", action="store_true", default=False, help="Use HTTP POST instead of GET")
parser.add_argument("--v6", action="store_true", default=False, help="Query AAAA instead of A")
parser.add_argument("--count", default=1000, type=int, help="Count of DoH packets to generate")
parser.add_argument("--server", default="doh-server", type=str, help="DoH server to query")
args = parser.parse_args()

dohclient = "doh/bin/doh-client"
with open(args.csvfile, newline='') as csvfile:
    urlreader = csv.reader(csvfile, delimiter=',')
    counter = 0
    if args.v6:
        qtype = 'AAAA'
    else:
        qtype = 'A'
    for row in urlreader:
        if counter == args.count:
            exit()
        domain = row[2]
        if args.post:
            output = subprocess.Popen([dohclient, '--cafile', 'selfsigned.pem', '--domain', args.server, '--qname', domain, '--post', '--qtype', qtype])
        else:
            output = subprocess.Popen([dohclient, '--cafile', 'selfsigned.pem', '--domain', args.server, '--qname', domain, '--qtype', qtype])
        print(counter)
        counter += 1
