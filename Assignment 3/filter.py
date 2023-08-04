import ipaddress
import sys

############################
#          Global          #
############################
network = ipaddress.ip_network("142.58.22.0/24")


class TCP_Header:
    def __init__(self, source_port=None, dest_port=None, seq_num=None, ack_num=None, data_offset=None,
                 reserved=None, control=None, window_size=None, checksum=None, URG_pointer=None, options=None):
        self.options = options  # Probably will not be present
        self.URG_pointer = URG_pointer  # If set, points to the first urgent data byte in the packet
        self.checksum = checksum    # Always correct and can be ignored
        self.window_size = window_size  # Number of bytes the sender is willing to receive
        self.control = control  # From left to right, these are: NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN.
        self.reserved = reserved    # Always set to 0
        self.data_offset = data_offset  # The number of 32-bit words in the TCP header. Indicates where the data begins.
        #  If the ACK control bit is set this field contains the value of the next sequence number
        #  the sender of the segment is expecting to receive.
        self.ack_num = ack_num
        self.seq_num = seq_num  # Always correct and can be ignored
        self.dest_port = dest_port  # The destination port number
        self.source_port = source_port  # The source port number


class ICMP_Header:
    def __init__(self, type=None, code=None, checksum=None, rest=None):
        self.rest = rest    # Contents depend on the ICMP type and code
        self.checksum = checksum    # always correct and can be ignored
        self.code = code    # For echo requests and replies, this field is usually 0.
        self.type = type    # 8 for echo request, 0 for an echo reply


class IP_Packet:
    def __init__(self, version=None, byte_length=None, identification=None, flags=None, fragment_offset=None,
                 time_to_live=None, protocol=None, header_checksum=None, source_IP=None, destination_IP=None,
                 ICMP_header=ICMP_Header(), TCP_header=TCP_Header(), malicious='no'):
        self.TCP_header = TCP_header
        self.ICMP_header = ICMP_header
        self.destination_IP = destination_IP
        self.source_IP = source_IP
        self.header_checksum = header_checksum
        self.protocol = protocol
        self.time_to_live = time_to_live
        self.fragment_offset = fragment_offset
        self.flags = flags
        self.identification = identification
        self.byte_length = byte_length
        self.version = version
        self.malicious = malicious


def within_subnet(ip_address):
    if ip_address in network:
        return True  # ip is in the network
    else:
        return False  # ip is not in the network


def egress_filtering(packets):
    for packet in packets:
        source_IP = packet.source_IP
        destination_IP = packet.destination_IP

        if not within_subnet(source_IP):
            packet.malicious = "yes"
        if within_subnet(destination_IP):
            packet.malicious = "yes"

    return


def ping_of_death(fragment_offset):
    return fragment_offset + 1500 > 65535


def two_ping_based_attacks(packets):
    for packet in packets:
        if ping_of_death(packet.fragment_offset):
            packet.malicious = "yes"


def syn_floods(content):
    pass


def string_to_binary(string):
    return bin(int(string, 16))[2:].zfill(len(string) * 4)


def binary_to_string(bin):
    return hex(int(bin, 2))[2:].zfill(len(bin) // 4)


def convert_to_IP(source):
    # Split the hexadecimal string into four segments of two characters each
    segments = [source[i:i + 2] for i in range(0, len(source), 2)]

    # Convert each segment to its decimal equivalent and join them to form the IP address
    ip_address_string = '.'.join(str(int(segment, 16)) for segment in segments)

    ip_address = ipaddress.ip_address(ip_address_string)

    return ip_address


def convert_to_protocol(param):
    result = "Unknown"
    match param:
        case "01":
            result = "ICMP"
        case "06":
            result = "TCP"
        case "17":
            result = "UDP"

    return result


def parse_icmp_header(packet, header_as_bin):
    # IP header ends at 160
    packet.ICMP_header.type = int(binary_to_string(header_as_bin[160:168]), 16)
    packet.ICMP_header.code = header_as_bin[168:176]
    packet.ICMP_header.checksum = header_as_bin[176:192]
    packet.ICMP_header.rest = header_as_bin[192:]


def parse_tcmp_header(packet, header_as_bin):
    # IP header ends at 160
    packet.TCP_header.source_port = header_as_bin[160:176]
    packet.TCP_header.dest_port = header_as_bin[176:192]
    packet.TCP_header.seq_num = header_as_bin[192:224]
    packet.TCP_header.ack_num = header_as_bin[224:256]
    packet.TCP_header.data_offset = header_as_bin[256:260]
    packet.TCP_header.reserved = header_as_bin[260:263]
    packet.TCP_header.control = header_as_bin[263:272]
    packet.TCP_header.window_size = header_as_bin[272:288]
    packet.TCP_header.checksum = header_as_bin[288:304]
    packet.TCP_header.URG_pointer = header_as_bin[304:320]
    packet.TCP_header.options = header_as_bin[320:]


def parse_ip_header(new_packet, header_as_bin):
    new_packet.version = binary_to_string(header_as_bin[0:4])
    length = binary_to_string(header_as_bin[16:32])
    new_packet.byte_length = int(length, 16)
    new_packet.identification = binary_to_string(header_as_bin[32:48])
    new_packet.flags = header_as_bin[48:51]
    fragment_offset = binary_to_string(header_as_bin[51:64])
    new_packet.fragment_offset = int(fragment_offset, 16) * 8  # Parsed as a number of octets -> *8 to get bytes
    new_packet.time_to_live = binary_to_string(header_as_bin[64:72])
    new_packet.protocol = convert_to_protocol(binary_to_string(header_as_bin[72:80]))
    new_packet.header_checksum = binary_to_string(header_as_bin[80:96])
    new_packet.source_IP = convert_to_IP(binary_to_string(header_as_bin[96:128]))
    new_packet.destination_IP = convert_to_IP(binary_to_string(header_as_bin[128:160]))


def parse_packet(list):
    header_as_string = ""
    for line in list:
        stripped_line = line[9:]
        header_as_string += stripped_line
    header_as_string = header_as_string.replace(' ', '')
    header_as_bin = string_to_binary(header_as_string)

    new_packet = IP_Packet()
    parse_ip_header(new_packet, header_as_bin)
    
    if new_packet.protocol == 'ICMP':
        parse_icmp_header(new_packet, header_as_bin)
    elif new_packet.protocol == 'TCP':
        parse_tcmp_header(new_packet, header_as_bin)

    return new_packet


def parse_contents(contents):
    list_of_packets = list()
    for line in contents:
        stripped_line = line.strip()
        if stripped_line.isdigit():  # A single digit signals a new packet
            if stripped_line == "1":  # On the first iteration, we have no information to parse yet
                current_list = list()
            else:
                new_packet = parse_packet(current_list)  # Parse a new packet with the current list
                list_of_packets.append(new_packet)  # Append the list to the list of parsed packets
                current_list = list()  # Create a new list
        else:
            current_list.append(stripped_line)
    last_packet = parse_packet(current_list)  # Parse a new packet with the current list
    list_of_packets.append(last_packet)
    return list_of_packets


def main(args):
    option_flag = args[1]  # == option
    filename = args[2]  # == filename

    with open(filename, 'r') as file:
        contents = file.readlines()

    packet_list = parse_contents(contents)

    if option_flag == '-i':
        # execute with egress filtering set
        egress_filtering(packet_list)
    elif option_flag == 'j':
        # Write a packet filter that filters out both pings of death and smurf attacks
        two_ping_based_attacks(packet_list)
    elif option_flag == '-k':
        # Write a packet filter that filters out SYN floods.
        syn_floods(packet_list)
    else:
        print("Option flag improperly set. Exiting.")

    i = 1
    for packet in packet_list:
        print(f"{i} " + packet.malicious)
        i += 1

    exit(0)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    argv = sys.argv
    main(argv)
