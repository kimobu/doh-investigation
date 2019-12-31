import csv
import subprocess

with open('majestic_million.csv', newline='') as csvfile:
    urlreader = csv.reader(csvfile, delimiter=',')
    count = 0
    for row in urlreader:
        if count == 100000:
            exit()
        domain = row[2]
        subprocess.Popen(['doh-client', '--cafile', 'selfsigned.pem', '--domain', 'doh-server', '--qname', domain, '--post'])
        count += 1
