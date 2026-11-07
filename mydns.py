import sys
from socket import socket, AF_INET, SOCK_DGRAM

#resource record types [RFC 3.2.2. TYPE values]
TYPE_A = 1 #host address
TYPE_NS = 2 #authoritative name server

# create DNS query message
def create_query(id, domain_name):
    # Query header [RFC 4.1.1. Header section format]
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                      ID                       |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    QDCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ANCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    NSCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ARCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    first_row = (id).to_bytes(2, byteorder='big')
    second_row = (0).to_bytes(2, byteorder='big')
    qdcount = (1).to_bytes(2, byteorder='big')
    ancount = (0).to_bytes(2, byteorder='big')
    nscount = (0).to_bytes(2, byteorder='big')
    arcount = (0).to_bytes(2, byteorder='big')
    header = first_row + second_row + qdcount + ancount + nscount + arcount

    # Question section [RFC 4.1.2. Question section format]
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                                               |
    # /                     QNAME                     /
    # /                                               /
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QTYPE                     |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QCLASS                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    # initialize qname as empty bytes
    qname = b''

    # split domain name into labels
    labels = domain_name.split('.')
    for label in labels:
        qname += len(label).to_bytes(1, byteorder='big')  # length byte
        qname += bytes(label, 'utf-8')  # label bytes
    # zero length byte as end of qname
    qname += (0).to_bytes(1, byteorder='big')

    qtype = (1).to_bytes(2, byteorder='big')
    qclass = (1).to_bytes(2, byteorder='big')
    question = qname + qtype + qclass

    return header + question

# parse byte_length bytes from index as unsigned integer, return number and index of next byte
def parse_unsigned_int(index, byte_length, response):
    num = int.from_bytes(
        response[index: index + byte_length], byteorder="big", signed=False)
    return num, index + byte_length

# parse name as label serie from index, return name and index of next byte
def parse_name(index, response):
    name = ''
    end = 0
    loop = True

    while loop:
        label_length = response[index]

        if label_length == 0:
            end = index + 1
            loop = False
        #pointer
        elif label_length >= int('11000000', 2):
            offset = int.from_bytes(response[index:index + 2], byteorder='big') - int('1100000000000000', 2)
            end = index + 2
            prev_name, _ = parse_name(offset, response)
            name += prev_name
            break
        # label
        else:
            index += 1
            label = response[index:index + label_length].decode('utf-8')
            name += label
            name += '.'
            index += label_length

    if name.endswith('.'):
        name = name.rstrip('.')

    return name, end

#parse 4 bytes from index as an IPv4 address string
def parse_ip(index, response):
    ip = ''
    for i in range(4):
        ip += str(response[index + i])
        if i < 3:
            ip += '.'
    return ip

#parse resource record from index, return record and index of next byte
#Resource record format [RFC 4.1.3. Resource record format]
def parse_rr(index, response):
    name, index = parse_name(index, response)
    rtype, index = parse_unsigned_int(index, 2, response)
    rclass, index = parse_unsigned_int(index, 2, response)
    ttl, index = parse_unsigned_int(index, 4, response)
    rdlength, index = parse_unsigned_int(index, 2, response)

    #RDATA depends on the type, only A and NS are needed
    data = None
    if rtype == TYPE_A and rdlength == 4:
        data = parse_ip(index, response)
    elif rtype == TYPE_NS:
        data, _ = parse_name(index, response)

    record = {'name': name, 'type': rtype, 'data': data}

    #skip over RDATA to the next record
    return record, index + rdlength

# response is the raw binary response received from server
def parse_response(response):
    # print('----- parse response -----')

    # dns message format [RFC 4.1. Format]
    # This example will only parse header and question sections.
    #
    # +---------------------+
    # |        Header       |
    # +---------------------+
    # |       Question      | the question for the name server
    # +---------------------+
    # |        Answer       | RRs answering the question
    # +---------------------+
    # |      Authority      | RRs pointing toward an authority
    # +---------------------+
    # |      Additional     | RRs holding additional information
    # +---------------------+

    # current byte index
    index = 0

    # print('Header section [RFC 4.1.1. Header section format]')
    # Header section [RFC 4.1.1. Header section format]
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                      ID                       |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    QDCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ANCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    NSCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ARCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    num, index = parse_unsigned_int(index, 2, response)
    # print(f'ID: {num}')

    # skip the next 2 bytes, i.e., second row
    index += 2

    num, index = parse_unsigned_int(index, 2, response)
    # print(f'QDCOUNT: {num}')

    num, index = parse_unsigned_int(index, 2, response)
    # print(f'ANCOUNT: {num}')
    ancount = num

    num, index = parse_unsigned_int(index, 2, response)
    # print(f'NSCOUNT: {num}')
    nscount = num

    num, index = parse_unsigned_int(index, 2, response)
    # print(f'ARCOUNT: {num}')
    arcount = num


    # print('Question section [RFC 4.1.2. Question section format]')
    # Question section [RFC 4.1.2. Question section format]
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                                               |
    # /                     QNAME                     /
    # /                                               /
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QTYPE                     |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QCLASS                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    name, index = parse_name(index, response)
    # print(f'QNAME: {name}')

    num, index = parse_unsigned_int(index, 2, response)
    # print(f'QTYPE: {num}')

    num, index = parse_unsigned_int(index, 2, response)
    # print(f'QCLASS: {num}')

    #Answer, Authority and Additional sections [RFC 4.1.3. Resource record format]
    answers = []
    for i in range(ancount):
        record, index = parse_rr(index, response)
        answers.append(record)

    authority = []
    for i in range(nscount):
        record, index = parse_rr(index, response)
        authority.append(record)

    additional = []
    for i in range(arcount):
        record, index = parse_rr(index, response)
        additional.append(record)

    #display reply content
    print('Reply received. Content overview:')
    print(f'\t{len(answers)} Answers.')
    print(f'\t{len(authority)} Intermediate Name Servers.')
    print(f'\t{len(additional)} Additional Information Records.')
    print('Answers section: ')
    for r in answers:
        if r['type'] == TYPE_A:
            print(f"\tName : {r['name']}\tIP: {r['data']}")
    print('Authority Section:')
    for r in authority:
        if r['type'] == TYPE_NS:
            print(f"\tName : {r['name']}\tName Server: {r['data']}")
    print('Additional Information Section:')
    for r in additional:
        #only IPv4, IPv6 is ignored
        if r['type'] == TYPE_A:
            print(f"\tName : {r['name']}\tIP : {r['data']}")

    return answers, authority, additional

# get domain-name and root-dns-ip from command line
if len(sys.argv) != 3:
    print('Usage: mydns domain-name root-dns-ip')
    sys.exit()
domain_name = sys.argv[1]
root_dns_ip = sys.argv[2]

# create UDP socket
socket = socket(AF_INET, SOCK_DGRAM)

# send DNS query
id = 1
print('-' * 64)
print(f'DNS server to query: {root_dns_ip}')
query = create_query(id, domain_name)
socket.sendto(query, (root_dns_ip, 53))
response, server_address = socket.recvfrom(2048)

# parse DNS response
answers, authority, additional = parse_response(response)

#check if the answers section has an IP for the domain name
def has_ip(answers):
    for r in answers:
        if r['type'] == TYPE_A:
            return True
    return False

#keep querying intermediate DNS servers until we get an IP
while not has_ip(answers):
    #pick a name server from the authority section that has an IP in the additional section
    next_ip = None
    for ns in authority:
        if ns['type'] != TYPE_NS:
            continue
        for r in additional:
            if r['type'] == TYPE_A and r['name'].lower() == ns['data'].lower():
                next_ip = r['data']
                break
        if next_ip is not None:
            break

    if next_ip is None:
        print('No intermediate DNS server IP found.')
        break

    #send DNS query to the intermediate server
    print('-' * 64)
    print(f'DNS server to query: {next_ip}')
    socket.sendto(query, (next_ip, 53))
    response, server_address = socket.recvfrom(2048)

    #parse DNS response
    answers, authority, additional = parse_response(response)