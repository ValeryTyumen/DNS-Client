'''
Copyright (c) 2014 Valera Likhosherstov <v.lihosherstov@gmail.com>
dns message structures
'''
import struct
import random


def pack(value):
    '''packs unsigned short
    '''
    return struct.pack('>H', value)

def unpack(data):
    '''unpacks unsigned short
    '''
    return struct.unpack('>H', data)[0]

def decode_string(message, offset):
    '''decodes string
    '''
    index = offset
    result = ''
    offset = 0
    while message[index] != 0:
        value = message[index]
        if (value>>6) == 3:
            next = unpack(message[index:index + 2])
            if offset == 0:
                offset = index + 2
            index = next ^ (3<<14)
        else:
            result += message[index + 1:index + 1 + 
                    value].decode('utf-8') + '.'
            index += value + 1
    if offset == 0:
        offset = index + 1
    result = result[:-1]
    return (offset, result)

query_type_names = { 1:'A', 2:'NS', 5:'CNAME', 15:'MX', 28:'AAAA' }
opcodes = { 0:'QUERY', 1:'IQUERY', 2:'STATUS' }
query_class_names = { 1:'IN' }
message_types = { 0:'QUERY', 1:'RESPONSE' }
responce_code_names = { 0:'No error', 1:'Format error', 
2:'Server failure', 3:'Name error', 4:'Not implemented', 5:'Refused' }


class MessageHeader:
    '''message header class
    '''


    def decode(self, message):
        '''decode header
        '''
        self.messageID = unpack(message[0:2])
        meta = unpack(message[2:4])
        self.rcode = (meta & 15)
        meta >>= 7
        self.ra = (meta & 1)
        meta >>= 1
        self.rd = (meta & 1)
        meta >>= 1
        self.tc = (meta & 1)
        meta >>= 1
        self.aa = (meta & 1)
        meta >>= 1
        self.opcode = (meta & 15)
        meta >>= 4
        self.qr = meta
        self.qd_count = unpack(message[4:6])
        self.an_count = unpack(message[6:8])
        self.ns_count = unpack(message[8:10])
        self.ar_count = unpack(message[10:12])
        return 12

    def generate_ID(self):
        '''generate random message ID
        '''
        return random.randint(0, 65535)

    def set_question_header(self, recursion_desired):
        '''set header for request
        '''
        self.messageID = self.generate_ID()
        self.qr = 0
        self.opcode = 0
        self.aa = 0
        self.tc = 0
        if recursion_desired:
            self.rd = 1
        else:
            self.rd = 0
        self.ra = 0
        self.rcode = 0
        self.qd_count = 1
        self.an_count = 0
        self.ns_count = 0
        self.ar_count = 0

    def encode(self):
        '''encode header
        '''
        result = pack(self.messageID)
        meta = 0
        meta |= self.qr
        meta <<= 1
        meta |= self.opcode
        meta <<= 4
        meta |= self.aa
        meta <<= 1
        meta |= self.tc
        meta <<= 1
        meta |= self.rd
        meta <<= 1
        meta |= self.ra
        meta <<= 7
        meta |= self.rcode
        result += pack(meta)
        result += pack(self.qd_count)
        result += pack(self.an_count)
        result += pack(self.ns_count)
        result += pack(self.ar_count)
        return result

    def print(self):
        '''for debug mode
        '''
        print('    Message ID: {0}'.format(hex(self.messageID)))
        print('    Query/Responce: {0}'.format(message_types[self.qr]))
        print('    Opcode: {0} ({1})'.format(self.opcode, 
            opcodes[self.opcode]))
        print('    Authoritative Answer: {0}'.format(bool(self.aa)))
        print('    TrunCation: {0}'.format(bool(self.tc)))
        print('    Recursion Desired: {0}'.format(bool(self.rd)))
        print('    Recursion Available: {0}'.format(bool(self.ra)))
        print('    Responce Code: {0} ({1})'.format(self.rcode, 
            responce_code_names[self.rcode]))
        print('    Questions: {0}'.format(self.qd_count))
        print('    Answers: {0}'.format(self.an_count))
        print('    Authority RRs: {0}'.format(self.ns_count))
        print('    Additional RRs: {0}'.format(self.ar_count))


class DNSQuestion:
    '''dns question class
    '''


    def decode(self, message, offset):
        '''decode question
        '''
        name = decode_string(message, offset)
        offset = name[0]
        self.name = name[1]
        self.type = unpack(message[offset:offset + 2])
        self.request_class = unpack(message[offset + 2:offset + 4])
        return offset + 4
    

    def set_question(self, name, IPv6):
        '''set question
        '''
        self.name = name
        if IPv6:
            self.type = 28
        else:
            self.type = 1
        self.request_class = 1

    def encode_name(self):
        '''encode question name
        '''
        name = self.name
        if name.endswith('.'):
            name = name[:-1]
        result = b''
        for domain_name in name.split('.'):
            result += struct.pack('B', len(domain_name))
            result += bytes(domain_name, 'utf-8')
        result += b'\x00'
        return result

    def encode(self):
        '''encode question
        '''
        result = self.encode_name()
        result += pack(self.type)
        result += pack(self.request_class)
        return result

    def print(self):
        '''for debug mode
        '''
        print('    Name: {0}'.format(self.name))
        print('    Type: {0}'.format(query_type_names[self.type]))
        print('    Class: {0}'.format(query_class_names[self.request_class]))


class AResourceData:
    '''resource data class
    '''


    def __init__(self, data):
        ip = struct.unpack('BBBB', data)
        self.ip = str(ip[0]) + '.' + str(ip[1]) + \
                '.' + str(ip[2]) + '.' + str(ip[3])

    def print(self):
        '''for debug mode
        '''
        print('    A: {0}'.format(self.ip))

class AAAAResourceData:
    '''resource data class
    '''


    def hexdump(self, data):
        '''dump data
        '''
        result = ''
        for byte in data:
            result += str(hex(256 + byte))[3:]
        return result 

    def __init__(self, data):
        self.data = data
        self.ip = ''
        dump = self.hexdump(data)
        for i in range(8):
            value = dump[i*4:i*4 + 4]
            for i in range(4):
                if value[i] != '0':
                    value = value[i:]
                    break
                if i == 3:
                    value = ''
            self.ip += value + ':'
        self.ip = self.ip[:-1]

    def print(self):
        '''for debug mode
        '''
        print('    AAAA: {0}'.format(self.ip))


class NSResourceData:
    '''resource data class
    '''

    
    def __init__(self, message, offset):
        self.name = decode_string(message, offset)[1]

    def print(self):
        '''for debug mode
        '''
        print('    NS: {0}'.format(self.name))


class MXResourceData:
    '''resource data class
    '''


    def __init__(self, message, offset):
        self.preference = unpack(message[offset:offset + 2])
        offset += 2
        self.mail_exchanger = decode_string(message, offset)[1]

    def print(self):
        '''for debug mode
        '''
        print('    MX: {0} {1}'.format(self.preference, 
                self.mail_exchanger))


class CNAMEResourceData:
    '''resource data class
    '''


    def __init__(self, message, offset):
        self.name = decode_string(message, offset)[1]

    def print(self):
        '''for debug mode
        '''
        print('    CNAME: {0}'.format(self.name))


class BinaryResourceData:
    '''resource data class
    '''


    def __init__(self, data):
        self.data = data

    def print(self):
        '''for debug mode
        '''
        print('    Data: {0}'.format(self.data))


class ResourceRecord:
    '''resource record class
    '''


    def set_resource_data(self, message, offset):
        '''set resource data
        '''
        rdata = message[offset: offset + self.rd_length]
        if self.type == 1:
            self.resource_data = AResourceData(rdata)
        elif self.type == 2:
            self.resource_data = NSResourceData(message, offset)
        elif self.type == 5:
            self.resource_data = CNAMEResourceData(message, offset)
        elif self.type == 15:
            self.resource_data = MXResourceData(message, offset)
        elif self.type == 28:
            self.resource_data = AAAAResourceData(rdata)
        else:
            self.resource_data = BinaryResourceData(rdata)

    def decode(self, message, offset):
        '''decode rr
        '''
        name = decode_string(message, offset)
        offset = name[0]
        self.name = name[1]
        self.type = unpack(message[offset:offset + 2])
        offset += 2
        self.request_class = unpack(message[offset:offset + 2])
        offset += 2
        self.ttl = struct.unpack('>I', message[offset: offset + 4])[0]
        offset += 4
        self.rd_length = unpack(message[offset:offset + 2])
        offset += 2
        self.set_resource_data(message, offset)
        return offset + self.rd_length

    def print(self):
        '''for debug mode
        '''
        print('    Name: {0}'.format(self.name))
        print('    Type: {0}'.format(query_type_names[self.type]))
        print('    Class: {0}'.format(
                query_class_names[self.request_class]))
        print('    TTL: {0}'.format(self.ttl))
        self.resource_data.print()


class DNSMessageFormat:
    '''dns message format class
    '''


    def encode(self, host_name, recursion_desired, IPv6):
        '''encode message
        '''
        message = b''
        self.header = MessageHeader()
        self.header.set_question_header(recursion_desired)
        message += self.header.encode()
        self.question = DNSQuestion()
        self.question.set_question(host_name, IPv6)
        message += self.question.encode()
        return message

    def decode(self, message):
        '''decode message
        '''
        self.header = MessageHeader()
        offset = self.header.decode(message)
        self.questions = []
        self.answers = []
        self.authority_RRs = []
        self.additional_RRs = []
        for i in range(self.header.qd_count):
            self.questions.append(DNSQuestion())
            offset = self.questions[i].decode(message, offset)
        for i in range(self.header.an_count):
            self.answers.append(ResourceRecord())
            offset = self.answers[i].decode(message, offset)
        for i in range(self.header.ns_count):
            self.authority_RRs.append(ResourceRecord())
            offset = self.authority_RRs[i].decode(message, offset)
        for i in range(self.header.ar_count):
            self.additional_RRs.append(ResourceRecord())
            offset = self.additional_RRs[i].decode(message, offset)

    def print(self):
        '''for debug mode
        '''
        print('MESSAGE HEADER')
        self.header.print()
        for i in range(self.header.qd_count):
            print('QUESTION[{0}]'.format(i))
            self.questions[i].print()
        for i in range(self.header.an_count):
            print('ANSWER[{0}]'.format(i))
            self.answers[i].print()
        for i in range(self.header.ns_count):
            print('AUTHORITY_RR[{0}]'.format(i))
            self.authority_RRs[i].print()
        for i in range(self.header.ar_count):
            print('ADDITIONAL_RR[{0}]'.format(i))
            self.additional_RRs[i].print()

    def print_result(self):
        '''output application result
        '''
        for answer in self.answers:
            if answer.type == 1 or answer.type == 28:
                print(answer.resource_data.ip)
