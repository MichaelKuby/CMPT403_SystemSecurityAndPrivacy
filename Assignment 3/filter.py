import ipaddress
import sys

############################
#          Global          #
############################

network = ipaddress.ip_network("142.58.22.0/24")


class TCP:
    def __init__(self, version=None, byte_length=None, identification=None, flags=None, fragment_offset=None,
                 time_to_live=None, protocol=None, header_checksum=None, source_IP=None, destination_IP=None,
                 source_port=None, dest_port=None, seq_num=None, ack_num=None, data_offset=None,
                 reserved=None, control=None, window_size=None, checksum=None, URG_pointer=None, malicious="no"):
        self.version = version
        self.byte_length = byte_length
        self.identification = identification
        self.flags = flags
        self.fragment_offset = fragment_offset
        self.time_to_live = time_to_live
        self.protocol = protocol
        self.header_checksum = header_checksum
        self.source_IP = source_IP
        self.destination_IP = destination_IP
        self.source_port = source_port  # The source port number
        self.dest_port = dest_port  # The destination port number
        self.seq_num = seq_num  # Always correct and can be ignored
        self.ack_num = ack_num
        self.data_offset = data_offset  # The number of 32-bit words in the TCP header. Indicates where the data begins.
        self.reserved = reserved  # Always set to 0
        self.control = control  # From left to right, these are: NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN.
        self.window_size = window_size  # Number of bytes the sender is willing to receive
        self.checksum = checksum  # Always correct and can be ignored
        self.URG_pointer = URG_pointer  # If set, points to the first urgent data byte in the packet
        self.malicious = malicious


class ICMP:
    def __init__(self, version=None, byte_length=None, identification=None, flags=None, fragment_offset=None,
                 time_to_live=None, protocol=None, header_checksum=None, source_IP=None, destination_IP=None,
                 type=None, code=None, checksum=None, rest=None, malicious="no"):
        self.version = version
        self.byte_length = byte_length
        self.identification = identification
        self.flags = flags
        self.fragment_offset = fragment_offset
        self.time_to_live = time_to_live
        self.protocol = protocol
        self.header_checksum = header_checksum
        self.source_IP = source_IP
        self.destination_IP = destination_IP
        self.type = type  # 8 for echo request, 0 for an echo reply
        self.code = code  # For echo requests and replies, this field is usually 0.
        self.checksum = checksum  # always correct and can be ignored
        self.rest = rest  # Contents depend on the ICMP type and code
        self.malicious = malicious


class PortsList:

    # permuted keys are always when checking outbound packets #
    outbound = 'outbound'
    inbound = 'inbound'

    def __init__(self):
        self.pairs = dict()

    def key(self, packet):
        source_IP = packet.source_IP
        source_port = int(packet.source_port, 2)
        destination_port = int(packet.dest_port, 2)
        destination_IP = packet.destination_IP
        return source_IP, destination_IP, source_port, destination_port

    def permute_key(self, key):
        return key[1], key[0], key[3], key[2]

    def new_connection(self, packet):
        key = self.key(packet)
        if key not in self.pairs:
            # These two IP's are not already communicating at this port
            self.pairs[key] = (True, False, False)  # (Syn, Syn-Ack, Ack)
            return True
        else:
            # These two ports are already in communication
            return False


    def existing_connection(self, packet, direction):
        key = self.key(packet)
        permuted_key = self.permute_key(key)

        if direction == self.inbound:
            if key in self.pairs:
                return True
        else:
            if permuted_key in self.pairs:
                return True
        return False

    def set_syn_ackd(self, packet):
        key = self.key(packet)
        permuted_key = self.permute_key(key)
        if self.pairs[permuted_key] == (True, False, False): # (Syn, Syn-Ack, Ack)
            self.pairs[permuted_key] = (True, True, False)   # (Syn, Syn-Ack, Ack)

    def set_connected(self, packet):
        key = self.key(packet)
        if self.pairs[key] == (True, True, False): # (Syn, Syn-Ack, Ack)
            self.pairs[key] = (True, True, True)   # (Syn, Syn-Ack, Ack)

    def del_connection(self, packet):
        key = self.key(packet)
        if packet.control['rst'] == 1 or packet.control['fin'] == 1:
            del self.pairs[key]

    def get_num_half_open(self, packet):
        key = self.key(packet)
        IP_pair = key[:2]
        i = 0
        for k in self.pairs:
            if IP_pair == k[:2]:
                if (self.pairs[k] == (True, True, False)) or (self.pairs[k] == (True, False, False)):   # (True, True, True) signals full connection
                    i += 1
        return i

    def display(self):
        for k, v in self.pairs.items():
            print(f'{k} : {v}')


####################################
#           Syn Floods             #
####################################


def new_connection(packet):
    if packet.control['syn'] == 1 and packet.control['ack'] == 0 \
            and packet.control['rst'] == 0 and packet.control['fin'] == 0:
        return True
    return False


def ack_half_open(packet):
    if packet.control['syn'] == 0 and packet.control['ack'] == 1 \
            and packet.control['rst'] == 0 and packet.control['fin'] == 0:
        return True
    return False


def syn_ack(packet):
    if packet.control['syn'] == 1 and packet.control['ack'] == 1 \
            and packet.control['rst'] == 0 and packet.control['fin'] == 0:
        return True
    return False


def disconnect(packet):
    if packet.control['rst'] == 1 or packet.control['fin'] == 1:
        return True
    return False


def within_subnet(ip_address):
    if ip_address in network:
        return True  # ip is in the network
    else:
        return False  # ip is not in the network


def syn_floods(packets):
    ports_tracker = PortsList()  # Keeps track of communicating ports and their status.

    for packet in packets:
        if not packet.protocol == "TCP":
            continue

        # Is this packet entering the network?
        if not within_subnet(packet.source_IP):
            direction = 'inbound'
            # Is this packet trying to create a new connection?
            if new_connection(packet):
                # Does the source_IP of the packet have less than 10 half open connections with this host?
                if ports_tracker.get_num_half_open(packet) < 10:
                    # Try to create a new connection. This may fail if the ports are already communicating
                    ports_tracker.new_connection(packet)
                else:
                    # The source_IP of the packet is trying to open > 10 half-open connects with host
                    packet.malicious = 'yes'

            # Packet is entering and responding to a syn request, we can ignore
            elif syn_ack(packet):
                continue

            # Is this packet acknowledging an existing half open connection?
            elif ack_half_open(packet) and ports_tracker.existing_connection(packet, direction):
                # Set the connection to full
                ports_tracker.set_connected(packet)

            # Is this a packet trying to signal a disconnection?
            elif disconnect(packet) and ports_tracker.existing_connection(packet, direction):
                # Remove the connection from the list of connected ports
                ports_tracker.del_connection(packet)
            else:
                # Will get here if packet makes no sense. Unknown situation.
                continue

        # Is this packet going out of the network?
        elif within_subnet(packet.source_IP):
            direction = 'outbound'
            # Is this a Syn-Ack response?
            if syn_ack(packet) and ports_tracker.existing_connection(packet, direction):
                # Set the connection to be syn_ackd
                ports_tracker.set_syn_ackd(packet)

            # Is this a packet trying to signal a disconnection?
            elif disconnect(packet) and ports_tracker.existing_connection(packet, direction):
                ports_tracker.del_connection(packet)

            # If this packet is an outbound syn or ack request, we don't care

####################################
#        Egress Filtering          #
####################################

def egress_filtering(packets):
    for packet in packets:
        source_IP = packet.source_IP
        destination_IP = packet.destination_IP

        if not within_subnet(source_IP):
            packet.malicious = "yes"
        if within_subnet(destination_IP):
            packet.malicious = "yes"

    return


####################################
#           Ping Attacks           #
####################################


def ping_of_death(packet):
    if packet.fragment_offset + 1500 > 65535:
        return True
    return False


def smurf_attack(packet):
    broadcast_address = network.broadcast_address
    if packet.destination_IP == broadcast_address:
        return True
    return False


def two_ping_based_attacks(packets):
    for packet in packets:
        if within_subnet(
                packet.destination_IP) and packet.protocol == 'ICMP' and packet.type == 8:  # Check that the destination IP is within our subnet
            if ping_of_death(packet):
                packet.malicious = "yes"
            if smurf_attack(packet):
                packet.malicious = "yes"


####################################
# Parse Packets into Useful Pieces #
####################################

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


def parse_icmp_header(header_as_bin):
    packet = ICMP()
    packet.version = binary_to_string(header_as_bin[0:4])
    length = binary_to_string(header_as_bin[16:32])
    packet.byte_length = int(length, 16)
    packet.identification = binary_to_string(header_as_bin[32:48])
    packet.flags = header_as_bin[48:51]
    fragment_offset = binary_to_string(header_as_bin[51:64])
    packet.fragment_offset = int(fragment_offset, 16) * 8  # Parsed as a number of octets -> *8 to get bytes
    packet.time_to_live = binary_to_string(header_as_bin[64:72])
    packet.protocol = convert_to_protocol(binary_to_string(header_as_bin[72:80]))
    packet.header_checksum = binary_to_string(header_as_bin[80:96])
    packet.source_IP = convert_to_IP(binary_to_string(header_as_bin[96:128]))
    packet.destination_IP = convert_to_IP(binary_to_string(header_as_bin[128:160]))
    packet.type = int(binary_to_string(header_as_bin[160:168]), 16)
    packet.code = header_as_bin[168:176]
    packet.checksum = header_as_bin[176:192]
    packet.rest = header_as_bin[192:]
    return packet


def parse_control_status(control_bin):
    names = ['urg', 'ack', 'psh', 'rst', 'syn', 'fin']
    bits = [int(bit) for bit in control_bin]
    return dict(zip(names, bits))


def parse_tcp_header(header_as_bin):
    packet = TCP()
    packet.version = binary_to_string(header_as_bin[0:4])
    length = binary_to_string(header_as_bin[16:32])
    packet.byte_length = int(length, 16)
    packet.identification = binary_to_string(header_as_bin[32:48])
    packet.flags = header_as_bin[48:51]
    fragment_offset = binary_to_string(header_as_bin[51:64])
    packet.fragment_offset = int(fragment_offset, 16) * 8  # Parsed as a number of octets -> *8 to get bytes
    packet.time_to_live = binary_to_string(header_as_bin[64:72])
    packet.protocol = convert_to_protocol(binary_to_string(header_as_bin[72:80]))
    packet.header_checksum = binary_to_string(header_as_bin[80:96])
    packet.source_IP = convert_to_IP(binary_to_string(header_as_bin[96:128]))
    packet.destination_IP = convert_to_IP(binary_to_string(header_as_bin[128:160]))
    packet.source_port = header_as_bin[160:176]
    packet.dest_port = header_as_bin[176:192]
    packet.seq_num = header_as_bin[192:224]
    packet.ack_num = header_as_bin[224:256]
    packet.data_offset = header_as_bin[256:260]
    packet.reserved = header_as_bin[260:266]
    packet.control = parse_control_status(header_as_bin[266:272])
    packet.window_size = header_as_bin[272:288]
    packet.checksum = header_as_bin[288:304]
    packet.URG_pointer = header_as_bin[304:320]
    packet.options = header_as_bin[320:336]
    return packet


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


def parse_binary(header_as_bin):
    protocol = convert_to_protocol(binary_to_string(header_as_bin[72:80]))

    if protocol == 'ICMP':
        return parse_icmp_header(header_as_bin)
    elif protocol == 'TCP':
        return parse_tcp_header(header_as_bin)


def parse_packet(list):
    header_as_string = ""
    for line in list:
        stripped_line = line[9:]
        header_as_string += stripped_line
    header_as_string = header_as_string.replace(' ', '')
    header_as_bin = string_to_binary(header_as_string)

    new_packet = parse_binary(header_as_bin)  # Up to here seems good

    return new_packet


def parse_contents(contents):
    list_of_packets = list()
    current_list = list()
    for line in contents:
        stripped_line = line.strip()
        if stripped_line.isdigit():  # A single digit signals a new packet
            if stripped_line == "1":
                continue    # On the first iteration, we have no information to parse yet
            else:
                new_packet = parse_packet(current_list)  # Parse a new packet with the current list
                list_of_packets.append(new_packet)  # Append the list to the list of parsed packets
                current_list = list()  # Create a new list
        else:
            current_list.append(stripped_line)
    last_packet = parse_packet(current_list)  # Parse a new packet with the current list
    list_of_packets.append(last_packet)
    return list_of_packets


####################################
#            Run Main              #
####################################


def main(args):
    option_flag = args[1]  # == option
    filename = args[2]  # == filename

    with open(filename, 'r') as file:
        contents = file.readlines()

    packet_list = parse_contents(contents)

    if option_flag == '-i':
        # execute with egress filtering set
        egress_filtering(packet_list)
    elif option_flag == '-j':
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


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    argv = sys.argv
    main(argv)
