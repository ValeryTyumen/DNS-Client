'''
Copyright (c) 2014 Valera Likhosherstov <v.lihosherstov@gmail.com>
tests
'''
import unittest
from query import MessageHeader, DNSQuestion, ResourceRecord, \
    AResourceData, AAAAResourceData, CNAMEResourceData, \
    DNSMessageFormat


class DNSqueryTestCase(unittest.TestCase):
    '''tests class
    '''


    def setUp(self):
        '''set up
        '''
        self.message1 = b'\x41\x21\x81\x80\x00\x01\x00\x02\x00' + \
            b'\x00\x00\x00\x04\x74\x61\x67\x73\x07\x62\x6c\x75' + \
            b'\x65\x6b\x61\x69\x03\x63\x6f\x6d\x00\x00\x01\x00' + \
            b'\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x96\x00' + \
            b'\x0b\x04\x74\x61\x67\x73\x03\x77\x64\x63\xc0\x11' + \
            b'\xc0\x2e\x00\x01\x00\x01\x00\x00\x0a\x27\x00\x04' + \
            b'\xad\xc0\xdc\x40'

    def test_header_decoding(self):
        '''test header
        '''
        data = b'\x80\xa5\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        header = MessageHeader()
        header.decode(data)
        self.assertEqual(32933, header.messageID)
        self.assertEqual(0, header.qr)
        self.assertEqual(0, header.opcode)
        self.assertEqual(0, header.tc)
        self.assertEqual(1, header.rd)
        self.assertEqual(1, header.qd_count)
        self.assertEqual(0, header.an_count)
        self.assertEqual(0, header.ns_count)
        self.assertEqual(0, header.ar_count)

    def test_header_encoding_and_decoding(self):
        '''test header
        '''
        header1 = MessageHeader()
        header1.set_question_header(True)
        data = header1.encode()
        header2 = MessageHeader()
        header2.decode(data)
        self.assertEqual(header1.messageID, header2.messageID)
        self.assertEqual(header1.qr, header2.qr)
        self.assertEqual(header1.opcode, header2.opcode)
        self.assertEqual(header1.tc, header2.tc)
        self.assertEqual(header1.rd, header2.rd)
        self.assertEqual(header1.qd_count, header2.qd_count)
        self.assertEqual(header1.an_count, header2.an_count)
        self.assertEqual(header1.ns_count, header2.ns_count)
        self.assertEqual(header1.ar_count, header2.ar_count)

    def test_question_decoding(self):
        '''test question
        '''
        data = b'\x01\x61\x10\x63\x6f\x6c\x6c\x65\x63\x74\x69' + \
                b'\x76\x65\x2d\x6d\x65\x64\x69\x61\x03\x6e' + \
                b'\x65\x74\x00\x00\x01\x00\x01'
        question = DNSQuestion()
        question.decode(data, 0)
        self.assertEqual('a.collective-media.net', question.name)
        self.assertEqual(1, question.type)
        self.assertEqual(1, question.request_class)

    def test_question_encoding_and_decoding_ipv4(self):
        '''test question
        '''
        question1 = DNSQuestion()
        question1.set_question('anytask.urgu.org', False)
        data = question1.encode()
        question2 = DNSQuestion()
        question2.decode(data, 0)
        self.assertEqual(question1.name, question2.name)
        self.assertEqual(question1.type, question2.type)
        self.assertEqual(question1.request_class, 
            question2.request_class)

    def test_rr_cname_decoding(self):
        '''test rr
        '''
        record = ResourceRecord()
        record.decode(self.message1, 34)
        self.assertEqual('tags.bluekai.com', record.name)
        self.assertEqual(5, record.type)
        self.assertEqual(1, record.request_class)
        self.assertEqual(150, record.ttl)
        self.assertEqual('tags.wdc.bluekai.com', 
            record.resource_data.name)

    def test_rr_a_decoding(self):
        '''test rr
        '''
        record = ResourceRecord()
        record.decode(self.message1, 57)
        self.assertEqual('tags.wdc.bluekai.com', record.name)
        self.assertEqual(1, record.type)
        self.assertEqual(1, record.request_class)
        self.assertEqual(2599, record.ttl)
        self.assertEqual('173.192.220.64', 
            record.resource_data.ip)    

    def test_decoding(self):
        '''test format
        '''
        format = DNSMessageFormat()
        format.decode(self.message1)
        self.assertEqual(16673, format.header.messageID)
        self.assertEqual(1, format.header.qr)
        self.assertEqual(0, format.header.opcode)
        self.assertEqual(0, format.header.tc)
        self.assertEqual(1, format.header.rd)
        self.assertEqual(1, format.header.ra)
        self.assertEqual(0, format.header.aa)
        self.assertEqual(0, format.header.rcode)
        self.assertEqual(1, format.header.qd_count)
        self.assertEqual(2, format.header.an_count)
        self.assertEqual(0, format.header.ns_count)
        self.assertEqual(0, format.header.ar_count)
        self.assertEqual('tags.bluekai.com', 
            format.questions[0].name)
        self.assertEqual(1, format.questions[0].type)
        self.assertEqual(1, format.questions[0].request_class)
        self.assertEqual('tags.bluekai.com', 
            format.answers[0].name)
        self.assertEqual(5, format.answers[0].type)
        self.assertEqual(1, format.answers[0].request_class)
        self.assertEqual(150, format.answers[0].ttl)
        self.assertEqual('tags.wdc.bluekai.com', 
            format.answers[0].resource_data.name)
        self.assertEqual('tags.wdc.bluekai.com', 
            format.answers[1].name)
        self.assertEqual(1, format.answers[1].type)
        self.assertEqual(1, format.answers[1].request_class)
        self.assertEqual(2599, format.answers[1].ttl)
        self.assertEqual('173.192.220.64', 
            format.answers[1].resource_data.ip)    

    def test_encoding_and_decoding(self):
        '''test format
        '''
        format1 = DNSMessageFormat()
        message = format1.encode('vk.com', True, False)
        format2 = DNSMessageFormat()
        format2.decode(message)
        self.assertEqual(format1.header.messageID, 
            format2.header.messageID)
        self.assertEqual(format1.header.qr, 
            format2.header.qr)
        self.assertEqual(format1.header.opcode, 
            format2.header.opcode)
        self.assertEqual(format1.header.tc, 
            format2.header.tc)
        self.assertEqual(format1.header.rd, 
            format2.header.rd)
        self.assertEqual(format1.header.qd_count, 
            format2.header.qd_count)
        self.assertEqual(format1.header.an_count, 
            format2.header.an_count)
        self.assertEqual(format1.header.ns_count, 
            format2.header.ns_count)
        self.assertEqual(format1.header.ar_count, 
            format2.header.ar_count)
        self.assertEqual(format1.question.name, 
            format2.questions[0].name)
        self.assertEqual(format1.question.type, 
            format2.questions[0].type)
        self.assertEqual(format1.question.request_class, 
            format2.questions[0].request_class)


if __name__ == "__main__":
    unittest.main()
