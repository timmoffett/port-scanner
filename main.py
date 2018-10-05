#!/usr/bin/python3

import argparse, socket, time, os, re, struct, subprocess, pdfkit
try:
    from scapy.all import *
except:
    pass

"""Port scanner as built/compiled by Timothy Moffett"""


def udp_scan(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    port = int(port)
    try:
        s.sendto('ping',(host, port))
        re, svr = s.recvfrom(255)
        print("{}/tcp is open".format(port))
    except Exception as e:
        try: errno, errtxt = e
        except ValueError:
            to_print.append(('{}/tcp  open'.format(port)))
    s.close()


def tcp_scan(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.connect((host, port))
        s.close()

        to_print.append(('{}/tcp  open'.format(port)))
    except Exception:
        pass

"""The following 4 functions
were created by phillipsme
https://github.com/phillips321/python-portscanner/blob/master/nmap.py
"""

def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "": b += dec2bin(int(q),8); outQuads -= 1
    while outQuads > 0: b += "00000000"; outQuads -= 1
    return b

def dec2bin(n,d=None):
    s = ""
    while n>0:
        if n&1: s = "1"+s
        else: s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d: s = "0"+s
    if s == "": s = "0"
    return s

def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

def returnCIDR(c):
    parts = c.split("/")
    print(parts)
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    ips=[]
    if subnet == 32: return bin2ip(baseIP)
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        print(ipPrefix)
        for i in range(2**(32-subnet)): ips.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
        return ips



def main():
    for address in ip_addresses:
        if tcp:
            if port_list:
                for port in port_list:
                    try:
                        tcp_scan(address, port)
                    except:
                        pass
            else:
                print('no port specified')
        if udp:
            if port_list:
                for port in port_list:
                    print(port)
                    try:
                        udp_scan(address, port)
                    except:
                        pass
            else:
                print('no port specified')
        if ping:
            try:
                p = subprocess.Popen(['ping', '-n', '1', address])
                p.wait()
                to_print.append(p.poll())
            except:
                pass
        if traceroute:
            try:
                p = subprocess.Popen(['tracert', address])
                p.wait()
                to_print.append(p.poll())
            except:
                try:
                    for i in range(1,30):
                        p = IP(dst=address, ttl=i) /UDP(dport=33434)
                        reply = sr1(pkt, verbose=0)
                        if reply is None:
                            break
                        elif reply.type == 3:
                            to_print.append('hop {}: {}'.format(i, address))
                            break
                        else:
                            to_print.append('hop {}: {}'.format(i, address))

                except:
                    pass
    print(to_print)
    try:
        if args.pdf:
            pdfkit.from_string("\n".join(to_print), args.pdf)
    except:
        pass




if __name__ == "__main__":
    """
    set_flags:
    
    This function will get arguments and set flags.
    """

    ip_addresses = []
    ports = []
    ping = False
    udp = False
    tcp = False
    traceroute = False
    timeout = 5
    to_print =""
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument('-T', '--target_ip', nargs='+', help="either -t or -f must be set. -t can be used\
     with a single ip, multiple ip's separated by spaces, or a range. -f is for files")
    parser.add_argument('-f', '--file', help='Read target ip\'s from a file (one ip per line)')
    parser.add_argument('-p', '--ports', nargs='+', help="Ports to scan. Syntax '-p 22' or '-p 1-1000'")
    parser.add_argument('-t', '--timeout', default=5, type=int, help='Timeout interval. Default value = 5')
    parser.add_argument('-sT', '--tcp', action='store_true', help='Scan TCP. This is the default if no scan type is selected')
    parser.add_argument('-sU', '--udp', action='store_true', help='Scan UDP')
    parser.add_argument('-sP', '--ping', action='store_true', help='Ping sweep')
    parser.add_argument('-tr', '--traceroute', action='store_true', help='Run traceroutes')
    parser.add_argument('-oP', '--pdf', help="print to pdf")
    args = parser.parse_args()
    timeout = args.timeout

    udp = args.udp

    try:
        if args.target_ip:
            if '/' in args.target_ip[0]:
                ip_addresses = returnCIDR(args.target_ip[0])
            elif len(args.target_ip) == 1:
                ip_addresses = args.target_ip
            else:
                ip_addresses += list(set(args.target_ip))
        else:
            with open(args.file) as f:
                ip_addresses = f.readlines()

        ip_addresses = [x.strip() for x in ip_addresses]
    except:
        print('error: must have at least one IP address')
        quit()


    port_list = []
    if args.ports:
        if '-' in args.ports[0]:
            ps, pe = args.ports[0].split('-')
            port_list = range(int(ps), int(pe)+1)
        elif len(args.ports) > 1:
            port_list += list(set(args.ports))
        elif len(args.ports) == 1:
            port_list = list(set(args.ports))
        else:
            pass
    else:
        pass
    
    timeout = 5
    if args.timeout:
        timeout = args.timeout

    # if scantype is not set
    # Otherwise set tcp to true (default scan)
    if args.udp:
        ping = args.ping
        tcp = args.tcp
        traceroute = args.traceroute
    elif args.ping:
        ping = args.ping
        tcp = args.tcp
        traceroute = args.traceroute
    elif args.traceroute:
        traceroute = args.traceroute
        tcp = args.tcp
    else:
        tcp = True

    main()
