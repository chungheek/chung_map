
'''
 Results class is a class that contains all the information needed
 for the chung_map.py script. It will save all the results of a scan
 and save it in this class and the class has built-in print functions
 to print the necessary data
'''


class Results:
    def __init__(self, host='', tcp=[], tcp_stealth=[], udp=[], os='', proto_arr=[]):
        self.host = host
        self.tcp = tcp
        self.tcp_stealth = tcp_stealth
        self.udp = udp
        self.os = os
        self.ip_protocols = proto_arr

    def set_host(self, host):
        self.host = host

    def set_tcp(self, tcp_arr):
        self.tcp = tcp_arr

    def set_tcp_stealth(self, tcp_arr):
        self.tcp_stealth = tcp_arr

    def set_udp(self, udp_arr):
        self.udp = udp_arr

    def set_os(self, os):
        self.os = os

    def set_ip_protocols(self, proto_arr):
        self.ip_protocols = proto_arr

    def print_host(self):
        if self.host != None:
            print(f'Host: {self.host}')
        else:
            print('Host NA')

    def print_os(self):
        if self.os != None:
            print(f'Operating System: {self.os}')
        else:
            print('Operating System: NA')

    def print_tcp(self):
        if len(self.tcp) > 0:
            print('Open TCP ports: ')
            for port in self.tcp:
                print(f'{port}')
        else:
            print("All TCP ports are closed")

    def print_tcp_stealth(self):
        if len(self.tcp_stealth) > 0:
            print('Open TCP stealth ports: ')
            for port in self.tcp_stealth:
                print(f'{port}')
        else:
            print("All TCP (stealth) ports are closed")

    def print_udp(self):
        if len(self.udp) > 0:
            print('Open UDP ports: ')
            for port in self.udp:
                print(f'{port}')
        else:
            print("All UDP ports are closed")

    def print_ip_proto(self):
        if len(self.ip_protocols) > 0:
            print('Open IP Protocols:')
            for x in range(0, len(self.ip_protocols)):
                print(f'{self.ip_protocols[x]}')
        else:
            print("No IP protocols")

    def print_results(self):
        self.print_os()
        self.print_tcp()
        self.print_tcp_stealth()
        self.print_udp()
