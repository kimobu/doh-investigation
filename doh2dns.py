import argparse
import pyshark
from scapy.all import *  # type: ignore
from tqdm import tqdm

parser = argparse.ArgumentParser(description="Convert DNS over HTTPS \
                                 query/responses to normal DNS")
parser.add_argument('--replay', '-r',
                    dest="replay_interface",
                    default="lo",
                    help="The interface on which to replay \
                          converted DNS packets.")
parser.add_argument('--sslkeylogfile', '-l',
                    dest="sslkeylogfile",
                    default="sslkeylog.txt",
                    help="The sslkeylog file which stores the client secrets")
parser.add_argument('--pcap', '-p',
                    dest="pcap",
                    required=True,
                    help="The PCAP file to process")
args = parser.parse_args()


def get_streams():
    print("[+] Retrieving streams")
    cap = pyshark.FileCapture(args.pcap,
                              override_prefs={
                                  'tls.keylog_file': args.sslkeylogfile
                              })
    cap.load_packets()
    streams = {}

    for packet in tqdm(cap, bar_format="{l_bar}{bar}"):
        if packet.__contains__('http2'):
            if packet.http2.streamid in streams:
                streams[packet.http2.streamid].append(packet)
            else:
                streams[packet.http2.streamid] = []
                streams[packet.http2.streamid].append(packet)
    print(f"[+] Identified {len(streams)} different streams")
    return streams


def process_streams(streams):
    print("[ ] Finding DNS answers...")
    dns_answers = []
    for streamid, packets in tqdm(streams.items(), bar_format="{l_bar}{bar}"):
        for packet in tqdm(packets, bar_format="{l_bar}{bar}"):
            if packet.__contains__('http2'):
                if packet.http2.get_field('dns_a')\
                        or packet.http2.get_field('dns_aaaa')\
                        or packet.http2.get_field('dns.count.answers') == '0':
                    # An answer was found.
                    # We can reconstruct a DNS packet using this information.
                    packetdata = {}
                    # Client and Server fields are reversed
                    packetdata['client'] = packet.ip.dst
                    packetdata['server'] = packet.ip.src
                    packetdata['query'] =\
                        packet.http2.get_field('dns_qry_name')
                    if packet.http2.get_field('dns_a'):
                        packetdata['answer'] =\
                            packet.http2.get_field('dns_a') or "NXDOMAIN"
                        packetdata['type'] = 'A'
                    else:
                        packetdata['answer'] =\
                            packet.http2.get_field('dns_aaaa') or "NXDOMAIN"
                        packetdata['type'] = 'AAAA'
                    dns_answers.append(packetdata)
    print(f"[+] Found {len(dns_answers)} DNS answers")
    return dns_answers


def craft_query(packetdata):
    dns_query = IP(dst=packetdata['server'],
                   src=packetdata['client'])\
                /UDP(sport=RandShort(),
                     dport=53)\
                /DNS(rd=1,
                     qd=DNSQR(qname=packetdata['query'],
                              qtype=packetdata['type']))
    return dns_query


def replay_packet(packet):
    send(packet.getlayer(IP), iface=args.replay_interface, verbose=0)


def main():
    print(f"[ ] Opening {args.pcap} with keylog {args.sslkeylogfile}")
    streams = get_streams()
    dns_answers = process_streams(streams)
    count = 1
    for ans in dns_answers:
        qry = craft_query(ans)
        replay_packet(qry)
        print(f"[+] Sent {count} of {len(dns_answers)} packets")
        count += 1


if __name__ == '__main__':
    main()
