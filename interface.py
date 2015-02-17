'''
Copyright (c) 2014 Valera Likhosherstov <v.lihosherstov@gmail.com>
DNS Console interface
'''
from client import DNSClient
import argparse


class ClientInterface:
    '''interface  class
    '''


    def __init__(self):
        parser = argparse.ArgumentParser(
            description='DNS client application')
        parser.add_argument('host_name', nargs=1, 
            metavar='name', help='Host name to request')
        parser.add_argument('--debug', '-d', action='store_true', 
            help='Debug mode')
        parser.add_argument('--nonrecursive', '-n', 
            action='store_false', help='Non recursive mode')
        parser.add_argument('--server', '-s', nargs=1, 
            metavar='server_IP', help='Non-default DNS server')    

        self.call_command(parser.parse_args())

    def call_command(self, parsed):
        '''call command
        '''
        if parsed.server is None:
            dns_client = DNSClient()
        else:
            dns_client = DNSClient(server=parsed.server[0])
        dns_client.send_query(parsed.host_name[0], 
            recursion_desired=parsed.nonrecursive, 
            debug_mode=parsed.debug)
        dns_client.disconnect()


if __name__ == '__main__':
    ClientInterface()
