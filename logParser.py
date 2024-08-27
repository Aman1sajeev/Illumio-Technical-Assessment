import csv
import argparse
from collections import defaultdict

protocol_number_to_keyword = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IPv4",
    5: "ST",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    10: "BBN-RCC-MON",
    11: "NVP-II",
    12: "PUP",
    13: "ARGUS (deprecated)",
    14: "EMCON",
    15: "XNET",
    16: "CHAOS",
    17: "UDP",
    18: "MUX",
    19: "DCN-MEAS",
    20: "HMP",
    21: "PRM",
    22: "XNS-IDP",
    23: "TRUNK-1",
    24: "TRUNK-2",
    25: "LEAF-1",
    26: "LEAF-2",
    27: "RDP",
    28: "IRTP",
    29: "ISO-TP4",
    30: "NETBLT",
    31: "MFE-NSP",
    32: "MERIT-INP",
    33: "DCCP",
    34: "3PC",
    35: "IDPR",
    36: "XTP",
    37: "DDP",
    38: "IDPR-CMTP",
    39: "TP++",
    40: "IL",
    41: "IPv6",
    42: "SDRP",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    45: "IDRP",
    46: "RSVP",
    47: "GRE",
    48: "DSR",
    49: "BNA",
    50: "ESP",
    51: "AH",
    52: "I-NLSP",
    53: "SWIPE (deprecated)",
    54: "NARP",
    55: "Min-IPv4",
    56: "TLSP",
    57: "SKIP",
    58: "IPv6-ICMP",
    59: "IPv6-NoNxt",
    60: "IPv6-Opts",
    61: None,
    62: "CFTP",
    63: None,
    64: "SAT-EXPAK",
    65: "KRYPTOLAN",
    66: "RVD",
    67: "IPPC",
    68: None,
    69: "SAT-MON",
    70: "VISA",
    71: "IPCV",
    72: "CPNX",
    73: "CPHB",
    74: "WSN",
    75: "PVP",
    76: "BR-SAT-MON",
    77: "SUN-ND",
    78: "WB-MON",
    79: "WB-EXPAK",
    80: "ISO-IP",
    81: "VMTP",
    82: "SECURE-VMTP",
    83: "VINES",
    84: "IPTM",
    85: "NSFNET-IGP",
    86: "DGP",
    87: "TCF",
    88: "EIGRP",
    89: "OSPFIGP",
    90: "Sprite-RPC",
    91: "LARP",
    92: "MTP",
    93: "AX.25",
    94: "IPIP",
    95: "MICP (deprecated)",
    96: "SCC-SP",
    97: "ETHERIP",
    98: "ENCAP",
    99: None,
    100: "GMTP",
    101: "IFMP",
    102: "PNNI",
    103: "PIM",
    104: "ARIS",
    105: "SCPS",
    106: "QNX",
    107: "A/N",
    108: "IPComp",
    109: "SNP",
    110: "Compaq-Peer",
    111: "IPX-in-IP",
    112: "VRRP",
    113: "PGM",
    114: None,
    115: "L2TP",
    116: "DDX",
    117: "IATP",
    118: "STP",
    119: "SRP",
    120: "UTI",
    121: "SMP",
    122: "SM (deprecated)",
    123: "PTP",
    124: "ISIS over IPv4",
    125: "FIRE",
    126: "CRTP",
    127: "CRUDP",
    128: "SSCOPMCE",
    129: "IPLT",
    130: "SPS",
    131: "PIPE",
    132: "SCTP",
    133: "FC",
    134: "RSVP-E2E-IGNORE",
    135: "Mobility Header",
    136: "UDPLite",
    137: "MPLS-in-IP",
    138: "manet",
    139: "HIP",
    140: "Shim6",
    141: "WESP",
    142: "ROHC",
    143: "Ethernet",
    144: "AGGFRAG",
    145: "NSH",
}


def parse_flow_logs(flow_log_file, lookup_file):
    tag_counts = defaultdict(int)
    port_protocol_counts = defaultdict(lambda: defaultdict(int))
    lookup_table = {}
    with open(lookup_file, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            key = (int(row['dstport'].lower()), row['protocol'].lower())
            lookup_table[key] = row['tag']
    # Parse the flow log file and count the matches
    with open(flow_log_file, 'r') as file:
        for line in file:
            fields = line.strip().split()
            if len(fields) == 14:
                dstport = int(fields[-8])
                protocol_number = int(fields[-7])
                protocol = protocol_number_to_keyword.get(protocol_number, 'Unknown')
                protocol = protocol.lower() if protocol else "Unknown"
                key = (dstport, protocol)
                if key in lookup_table:
                    tag = lookup_table[key].lower()
                    tag_counts[tag] += 1
                else:
                    tag_counts['Untagged'] += 1
                port_protocol_counts[dstport][protocol] += 1

    return tag_counts, port_protocol_counts


def write_output_files(tag_counts, port_protocol_counts, tag_output_file, port_output_file):
    # Write tag counts to a file
    with open(tag_output_file, 'w') as file:
        writer = csv.writer(file)
        writer.writerow(['Tag', 'Count'])
        for tag, count in tag_counts.items():
            writer.writerow([tag, count])

    # Write port/protocol combination counts to a file
    with open(port_output_file, 'w') as file:
        writer = csv.writer(file)
        writer.writerow(['Port', 'Protocol', 'Count'])
        for port, protocol_counts in port_protocol_counts.items():
            for protocol, count in protocol_counts.items():
                writer.writerow([port, protocol, count])


def main():
    parser = argparse.ArgumentParser(description='Parse flow logs and generate tag and port/protocol counts.')
    parser.add_argument('flow_log_file', help='Path to the flow log file')
    parser.add_argument('lookup_file', help='Path to the lookup table file')
    parser.add_argument('-t', '--tag_output_file', default='tag_counts.csv',
                        help='Path to the output file for tag counts (default: tag_counts.csv)')
    parser.add_argument('-p', '--port_output_file', default='port_protocol_counts.csv',
                        help='Path to the output file for port/protocol counts (default: port_protocol_counts.csv)')

    args = parser.parse_args()

    tag_counts, port_protocol_counts = parse_flow_logs(args.flow_log_file, args.lookup_file)

    write_output_files(tag_counts, port_protocol_counts, args.tag_output_file, args.port_output_file)


if __name__ == '__main__':
    main()
