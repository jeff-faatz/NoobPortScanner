#!/usr/bin/env python3

#------------------------------------------------------#
#----------- Noob Port Scanner  Version 1.0 -----------#
#--------------- Written by Jeff Faatz ----------------#
#--------------- Created February 2023 ----------------#
#----------- https://github.com/jeff-faatz ------------#
#-------------- https://jeffreyfaatz.com --------------#
#------------------------------------------------------#

import argparse
import socket
import threading
import ipaddress
import pyfiglet

ascii_banner = pyfiglet.figlet_format("NoobPortScanner")
print(ascii_banner)

class PortScanner:
    def __init__(self, host, ports):
        self.host = host
        self.ports = ports
        self.open_ports = []

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.host, port))
            self.open_ports.append(port)
            sock.close()
        except:
            pass

    def scan(self):
        for port in self.ports:
            t = threading.Thread(target=self.scan_port, args=(port,))
            t.start()

        for t in threading.enumerate():
            if t != threading.current_thread():
                t.join()

        return self.open_ports

class NetworkScanner:
    def __init__(self, network):
        self.network = network
        self.hosts = []

    def scan_host(self, ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((str(ip), 80))
            sock.close()
            self.hosts.append(str(ip))
        except:
            pass

    def scan(self):
        for ip in self.network:
            t = threading.Thread(target=self.scan_host, args=(ip,))
            t.start()

        for t in threading.enumerate():
            if t != threading.current_thread():
                t.join()

        return self.hosts

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan a network to determine what hosts are active and what ports are open.')
    parser.add_argument('host', nargs='?', help='IP address or hostname of the target machine')
    parser.add_argument('-p', '--port', help='Port number to scan (e.g. 80) or a range of ports to scan (e.g. 1-1024) - Default is 1-1025')
    parser.add_argument('-o', '--output', help='Output file to write results to')
    parser.add_argument('-n', '--network', help='IP range to scan for active hosts (e.g. 192.168.1.1-192.168.1.254 or 192.168.1.0/24)')
    args = parser.parse_args()

    if args.network:
        if '-' in args.network:
            start_ip, end_ip = args.network.split('-')
            network = list(ipaddress.summarize_address_range(ipaddress.IPv4Address(start_ip), ipaddress.IPv4Address(end_ip)))
        else:
            network = [ip for ip in ipaddress.IPv4Network(args.network)]

        scanner = NetworkScanner(network)
        active_hosts = scanner.scan()

        if len(active_hosts) > 0:
            print('The following hosts are online:')
            print(*active_hosts, sep='\n')
        else:
            print('No active hosts found.')
    else:
        host = args.host
        if args.port:
            if '-' in args.port:
                start_port, end_port = args.port.split('-')
                ports = range(int(start_port), int(end_port) + 1)
            else:
                ports = [int(args.port)]
        else:
            ports = range(1, 1025)

        scanner = PortScanner(host, ports)
        open_ports = scanner.scan()

        if len(open_ports) > 0:
            print(f'The following ports are open on {host}:')
            print(*open_ports, sep='\n')
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(f'The following ports are open on {host}:\n')
                    for port in open_ports:
                        f.write(f'{ports}\n')
						
        else:
            print(f'No open ports found on {host}.')
