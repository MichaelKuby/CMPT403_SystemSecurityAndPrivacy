import ipaddress
import sys

############################
#          Global          #
############################
network = ipaddress.ip_network("142.58.22.0/24")


class Packet:
    def __init__(self, version=None, byte_length=None, identification=None, flags=None, fragment_offset=None,
                 time_to_live=None, protocol=None, header_checksum=None, source_IP=None, destination_IP=None,
                 options=None, rest=None, malicious='no'):
        self.malicious = malicious
        self.rest = rest
        self.options = options
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


def within_subnet(ip_address):
    if ip_address in network:
        return True     # ip is in the network
    else:
        return False    # ip is not in the network


def egress_filtering(packets):

    for packet in packets:
        source_IP = packet.source_IP
        destination_IP = packet.destination_IP

        if not within_subnet(source_IP):
            packet.malicious = "yes"
        if within_subnet(destination_IP):
            packet.malicious = "yes"

    return


def two_ping_based_attacks(content):
    pass


def syn_floods(content):
    pass




def string_to_binary(string):
    return bin(int(string, 16))[2:].zfill(len(string) * 4)


def binary_to_string(bin):
    return hex(int(bin, 2))[2:].zfill(len(bin)//4)


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


def parse_packet(list):
    header_as_string = ""
    for line in list:
        stripped_line = line[9:]
        header_as_string += stripped_line
    header_as_string = header_as_string.replace(' ', '')
    header_as_bin = string_to_binary(header_as_string)

    new_packet = Packet()
    new_packet.version = binary_to_string(header_as_bin[0:4])
    length = binary_to_string(header_as_bin[16:32])
    new_packet.byte_length = int(length, 16)
    new_packet.identification = binary_to_string(header_as_bin[32:48])
    new_packet.flags = header_as_bin[48:51]
    fragment_offset = binary_to_string(header_as_bin[51:64])
    new_packet.fragment_offset = int(fragment_offset, 16)
    new_packet.time_to_live = binary_to_string(header_as_bin[64:72])
    new_packet.protocol = convert_to_protocol(binary_to_string(header_as_bin[72:80]))
    new_packet.header_checksum = binary_to_string(header_as_bin[80:96])
    new_packet.source_IP = convert_to_IP(binary_to_string(header_as_bin[96:128]))
    new_packet.destination_IP = convert_to_IP(binary_to_string(header_as_bin[128:160]))
    new_packet.options = binary_to_string(header_as_bin[160:192])
    new_packet.rest = binary_to_string(header_as_bin[192:])

    return new_packet

def parse_contents(contents):
    list_of_packets = list()
    for line in contents:
        stripped_line = line.strip()
        if stripped_line.isdigit():     # A single digit signals a new packet
            if stripped_line == "1":    # On the first iteration, we have no information to parse yet
                current_list = list()
            else:
                new_packet = parse_packet(current_list) # Parse a new packet with the current list
                list_of_packets.append(new_packet)      # Append the list to the list of parsed packets
                current_list = list()                   # Create a new list
        else:
            current_list.append(stripped_line)
    last_packet = parse_packet(current_list)  # Parse a new packet with the current list
    list_of_packets.append(last_packet)
    return list_of_packets


def main(args):
    option_flag = args[1]   # == option
    filename = args[2]      # == filename

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
