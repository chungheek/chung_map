from scapy.all import *
import sys
import ipaddress
from results import Results

# Can set timeout for sr/sr1 methods
timeout_set = 2
flags_arr = ['-sT', '-sS', '-sS' '-sU',
             '-O', '-sO', '-O,', ',', '-', '--top-100-ports']
top100 = 'top100ports.txt'

'''
Sample commands to use:
- chung_map -sT -p 20-100, 130-150, 400-500 scanme.nmap.org
- chung_map -sU –top-100-ports scanme.nmap.org
- chung_map -O scanme.nmap.org
- chung_map -sO scanme.nmap.org *(prints out None initially then the list of open ports)*
- chung_map -sT {file.txt} *please use .txt for the file to read. Automatically performs
  -sT scan on ports 20-25*
  - eg. chung_map -sT hosts.txt
- chung_map -sT {cidr address} *Make sure host bits are not set. Automatically performs
  -sT scan on ports 20-25*
  - eg. chung_map -sT 192.168.0.0/30

*Top 100 ports taken from performing
sudo nmap --top-ports 100 localhost -v -oG -
on kali linux as laid out in https://security.stackexchange.com/a/78625
if --top-100 flag is set then it will get the top 100 ports from the file top100
'''

result = Results()

'''
 The main function is where all the conditional logic will occur
 for the different flags set and perform each action according to
 the flags set by the user
'''


def main():
    flags = sys.argv
    arg_count = len(sys.argv)
    if arg_count > 2:  # if we have a command line argument
        target = sys.argv[arg_count - 1]
        if any(flag in target for flag in flags_arr):
            print("Incorrect use of flags. Please try again.")
            sys.exit(0)
        # Takes into account for CIDR notation
        # Will automatically perform st_scan on ports 20-25
        elif '/' in target:
            targets = cidr_list(target)
            targets_arr = []
            for target in targets:
                results_obj = Results(target)
                results_obj.set_tcp(st_scan(target, ['-p', '20-25']))
                targets_arr.append(results_obj)
            for target in targets_arr:
                target.print_host()
                target.print_tcp()
        # Takes into account for file
        # Will automatically perform st_scan on ports 20-25
        elif '.txt' in target:
            f = open(target, "r")
            targets = [line.rstrip() for line in f.readlines()]
            targets_arr = []
            for target in targets:
                results_obj = Results(target)
                results_obj.set_tcp(st_scan(target, ['-p', '20-25']))
                targets_arr.append(results_obj)
            for target in targets_arr:
                target.print_host()
                target.print_tcp()
        elif '-p' in flags and '-sT' in flags and target:
            result.set_tcp(st_scan(target, flags))
            result.print_tcp()
        elif '-p' in flags and '-sS' in flags and target:
            result.set_tcp_stealth(ss_scan(target, flags))
            result.print_tcp_stealth()
        elif '-p' in flags and '-sU' in flags and target:
            result.set_udp(su_scan(target, flags))
            result.print_udp()
        elif '--top-100-ports' in flags and target:
            f = open(top100, "r")
            ports = f.readline()
            ports_list = ["-p", ports]
            if '-sT' in flags:
                result.set_tcp(st_scan(target, ports_list))
                result.print_tcp()
            elif '-sS' in flags:
                result.set_tcp_stealth(ss_scan(target, ports_list))
                result.print_tcp_stealth()
            elif '-sU' in flags:
                result.set_udp(su_scan(target, ports_list))
                result.print_udp()
        elif '-O' in flags and target:
            os_result = o_scan(target)
            if os_result == None:
                print('Could not determine OS')
            else:
                result.set_os(os_result)
                result.print_os()
        elif '-sO' in flags and target:
            so_result = so_scan(target)
            result.set_ip_protocols(so_result)
            result.print_ip_proto()
        else:
            print('Incorrect use of flags. Please try again.')
            sys.exit(0)

    if arg_count <= 2:
        print(
            "chung_map: 1.0\nUsage: chung_map [flags] [target]\n -sT: TCP connect() scan\n -sS: TCP connect() stealth scan\n -sU: UDP scan\n -O: OS detection scan\n -sO: IP Protocol scan\n -[target] can be in CIDR notation, a text file, or a domain name\n -p {port/port-ranges}: specify ports (make sure there are no spaces between numbers, commas, and ranges\n   For eg. '20-25,80,55-60'")
        sys.exit(0)


'''
 st_scan(target, flags) like nmap when -sT flag is set it will
 parse and perform a tcp_connect_scan of each port specified
'''


def st_scan(target, flags):
    success_ports = []
    port_list = ports_parser(flags)
    for port in port_list:
        port_num = tcp_connect_scan(target, port)
        if type(port_num) == int:
            success_ports.append(port_num)
    return success_ports


'''
 ss_scan(target, flags) like nmap when -sS flag is set it will
 parse and perform a tcp_connect_scan of each port specified, but
 with stealth set to True
'''


def ss_scan(target, flags):
    success_ports = []
    port_list = ports_parser(flags)
    for port in port_list:
        port_num = tcp_connect_scan(target, port, True)
        if type(port_num) == int:
            success_ports.append(port_num)
    return success_ports


'''
 su_scan(target, flags) like nmap when -sU flag is set it will
 parse and perform a udp_scan of each port specified.
'''


def su_scan(target, flags):
    success_ports = []
    port_list = ports_parser(flags)
    for port in port_list:
        port_num = udp_scan(target, port)
        if type(port_num) == int:
            success_ports.append(port_num)
    return success_ports


'''
 o_scan(target, flags) like nmap when -O flag it will
 perform an os_scan to see the operating system of the
 target
'''


def o_scan(target):
    operating_system = os_scan(target)
    return operating_system


'''
 o_scan(target, flags) like nmap when -O flag it will
 perform an os_scan to see the operating system of the
 target
'''


def so_scan(target):
    ip_protocols = ip_protocol_scan(target)
    return ip_protocols


'''
tcp_connect_scan's logic is similar to methods found in
source [5] and follows the logic laid out in source [3]
if a syn+ack is received then we know the port is open
and we can reset the port after verifying
'''


def tcp_connect_scan(target, port, stealth=False):
    ip = IP(dst=target)
    tcp = TCP(dport=port, flags='S')
    ans = sr1(ip/tcp, timeout=timeout_set, verbose=0)
    if ans == None:
        #print(f'{port} is closed on {target}')
        return
    # Connection is successfuly and can reset from our side
    if ans.getlayer(TCP).flags == 0x12:
        if stealth:
            reset_connection(target, port, True)
        else:
            reset_connection(target, port)
        # Will return port that is successfully connected
        return port
    elif ans.getlayer(TCP).flags == 0x14:
        #print(f'{port} is closed on {target}')
        pass


'''
udp_scan's logic is also similar to methods found in
source [5] and follows the logic laid out in source [3]
it checks to see if the packet has an ICMP layer and will
disregard packets that have type and code equal to 3 and
also disregard filtered packets
'''


def udp_scan(target, port):
    ip = IP(dst=target)
    udp = UDP(dport=port)
    ans = sr1(ip/udp, timeout=timeout_set, verbose=0)
    if ans == None:
        #print(f'{port} is closed on {target}')
        return
    elif ans.haslayer(ICMP):
        # If packet has type and code = 3 then it means port is closed
        if(int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) == 3):
            #print(f'{port} is closed on {target}')
            pass
        # if packet has code 1, 2, 9, 10, 13 it means it is filtered
        elif (int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
            #print(f'{port} is filtered on {target}')
            pass
        return
    # Otherwise if packet is UDP then port is open
    elif ans.haslayer(UDP):
        return port


'''
os_scan was primarily created from using source [2] and
uses TTL to discern between the main OS's. TCP window was
taken into consideration, but there were some issues
'''


def os_scan(target):
    ip = IP(dst=target)
    tcp = TCP(dport=80, flags='S')
    # TCP 3-way Handshake
    ans = sr1(ip/tcp, timeout=timeout_set, verbose=0)
    if ans == None:
        return
    tcp.seq = ans.ack
    tcp.ack = ans.seq + 1
    tcp.flags = 'A'
    # X = random payload data
    ans = sr1(ip/tcp/"X", verbose=0)
    reset_connection(target, 80)
    if ans == None:
        return
    # Using TTL to discern OS
    # Tested with TCP.window, but had weird results so it is excluded from this code
    else:
        if ans.ttl == 64:
            return 'Linux'
        if ans.ttl == 128:
            return 'Windows'
        if ans.ttl == 255:
            return 'Cisco Router'


'''
ip_protocol_scan was created with the logic laid out in source [6]
'''


def ip_protocol_scan(target):
    ip_protocols = []
    # (0,255) will go through all 8 bits
    ip = IP(dst=target, proto=(0, 255))
    ans, unans = sr(ip/"SCAPY", retry=2, timeout=timeout_set, verbose=0)
    if ans == None:
        pass
    else:
        ans.show_summary = False
        ans.summary(lambda s, r: ip_protocol_filter(r, ip_protocols))
    return ip_protocols

# https://stackoverflow.com/a/53648372/6889483
# A straightforward way to make a list of all the IP
# addresses given the subnet mask


def cidr_list(target):
    return [str(ip) for ip in ipaddress.IPv4Network(target)]

# Helper function of ip_protocol_scan


def ip_protocol_filter(packet, arr):
    if packet.haslayer(ICMP):
        # If packet has type and code = 3 then it means port is closed
        if(int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) == 3):
            return
        # if packet has code 1, 2, 9, 10, 13 it means it is filtered
        elif (int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
            #print(f'{port} is filtered on {target}')
            return
    arr.append(packet.sprintf('%proto%'))

# Takes in a string with no spaces and creates an array/list
# of all the ports that need to be processed


def ports_parser(flags_string):
    idx = flags_string.index('-p')
    ports = flags_string[idx+1]
    if ',' in ports or '-' in ports:
        if '-' in ports:
            port_list = parseIntSet(ports)
        else:
            port_list = [int(port) for port in ports.split(",")]
    else:
        port_list = [int(ports)]
    return port_list

# Sends a RST packet to the specified target/port


def reset_connection(target, port, stealth=False):
    ip = IP(dst=target)
    if stealth:
        tcp = TCP(dport=port, flags='R')
    else:
        tcp = TCP(dport=port, flags='AR')
    return sr(ip/tcp, timeout=timeout_set, verbose=0)

# Function taken from https://stackoverflow.com/a/712483/6889483


def parseIntSet(inputstr=""):
    selection = []
    invalid = []
    # tokens are comma seperated values
    tokens = [x.strip() for x in inputstr.split(',')]
    for i in tokens:
        if len(i) > 0:
            if i[:1] == "<":
                i = "1-%s" % (i[1:])
        try:
            # typically tokens are plain old integers
            selection.append(int(i))
        except:
            # if not, then it might be a range
            try:
                token = [int(k.strip()) for k in i.split('-')]
                if len(token) > 1:
                    token.sort()
                    # we have items seperated by a dash
                    # try to build a valid range
                    first = token[0]
                    last = token[len(token)-1]
                    for x in range(first, last+1):
                        selection.append(x)
            except:
                # not an int and not a range...
                invalid.append(i)
    # Report invalid tokens before returning valid selection
    if len(invalid) > 0:
        print("Invalid set: " + str(invalid))
    return selection


if __name__ == '__main__':
    main()


# Sources:
# 1. https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/service_discovery/index.html
# 2. https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/os_detection/index.html
# 3. https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/
# 4. https://www.uv.mx/personal/angelperez/files/2018/10/scanning_texto.pdf
# 5. https://github.com/interference-security/Multiport/blob/master/multiport.py
# 6. https://scapy.readthedocs.io/en/latest/usage.html
# 7. https://www.mmu.ac.uk/media/mmuacuk/content/documents/school-of-computing-mathematics-and-digital-technology/blossom/Scapy-Scans,-Trace-Routes-and-TCP-Handshakes.pdf
