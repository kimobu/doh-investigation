import argparse
import re
import subprocess
import string
from base64 import b64decode

parser = argparse.ArgumentParser(description="Convert DNS over HTTPS query/responses to normal DNS")
parser.add_argument('--sniff', '-s', dest="sniff_interface", default="lo", help="The interface on which to sniff for DoH packets.")
parser.add_argument('--replay', '-r', dest="replay_interface", default="lo", help="The interface on which to replay converted DNS packets.")
parser.add_argument('--sslkeylogfile', '-l', dest="sslkeylogfile", default="sslkeylog.txt", help="The sslkeylog file which stores the client secrets")
parser.add_argument('--pcap', '-p', dest="pcap", required=True, help="The PCAP file to process")
args = parser.parse_args()

def read_file(filename):
    sslkeylogfileoptions = "ssl.keylog_file:" + args.sslkeylogfile
    process = subprocess.Popen(['tshark','-r',filename,'-o',sslkeylogfileoptions], stdout=subprocess.PIPE)
    return process.stdout.read()

def find_get_queries(pcapdata):
    lines = pcapdata.splitlines()
    matches = []
    for line in lines:
        m = re.findall(r"GET.*dns=(.*)\b", str(line))
        if m:
            matches.append(m[0])
    return matches

def print_queries(queries):
    for query in queries:
        fail = False
        try:
            decoded = b64decode(query)
        except:
            query = query + "="
            try:
                decoded = b64decode(query)
            except:
                query = query + "="
                try:
                    decoded = b64decode(query)
                except:
                    decoded = "Failed to find a valid base64 encoded string"
                    fail = True
        if fail == False:
            domain = ""
            for char in decoded:
                if chr(char) in string.printable:
                    domain += chr(char)
                elif char == 0x03:
                    domain += "."
            print(domain)

def replay_packet(packet):
    send(packet.getlayer(IP), iface=args.replay_interface, verbose=0)

if __name__ == '__main__':
    pcapdata = read_file(args.pcap)
    doh_get_queries = find_get_queries(pcapdata)
    print_queries(doh_get_queries)
