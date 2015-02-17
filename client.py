'''
Copyright (c) 2014 Valera Likhosherstov <v.lihosherstov@gmail.com>
DNS client engine
'''
import socket
from query import DNSMessageFormat


class DNSClient:
    '''dns client class
    '''


    def __init__(self, server='8.8.8.8'):
        self.socket = socket.socket(socket.AF_INET, 
            socket.SOCK_DGRAM)
        self.socket.settimeout(5)
        self.connect_server(server)

    def connect_server(self, server):
        '''connection
        '''
        try:
            self.socket.connect((server, 53))
        except Exception:
            print('Unable to connect to server {0}'.format(server))
            return False
        self.server = server
        return True

    def send_query(self, request, recursion_desired=True, 
            debug_mode=False, IPv6=False):
        '''request
        '''
        format = DNSMessageFormat()
        query = format.encode(request, recursion_desired, IPv6)
        self.socket.send(query)
        try:
            responce = self.socket.recv(1024)
        except Exception:
            print('Time Out: {0}'.format(self.server))
            exit(0)
        format.decode(responce)

        if debug_mode:
            print('#################  RESPONCE from {0} ' \
                ' ##################'.format(self.server))
            format.print()
        
        if len(format.answers) > 0:
            if debug_mode:
                print('################################' \
                    '############################')
            format.print_result()
            self.socket.close()
        elif not recursion_desired:
            for rr in format.additional_RRs:
                if self.connect_server(rr.resource_data.ip):
                    ipv6 = (rr.type == 28)
                    self.send_query(request, recursion_desired=False, 
                        debug_mode=debug_mode, IPv6=ipv6)

    def disconnect(self):
        '''disconnect
        '''
        self.socket.close()


if __name__ == '__main__':
    client = DNSClient(server='8.8.8.8')
    client.send_query('vk.com', recursion_desired=False, debug_mode=False)
    client.disconnect()
