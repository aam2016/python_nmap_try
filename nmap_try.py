#!/usr/bin/env python3

import sys
import nmap


print("python-nmap version -", nmap.__version__)
try:
    nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
except nmap.PortScannerError:
    print('Nmap not found', sys.exc_info()[0])
    sys.exit(0)
except:
    print("Unexpected error:", sys.exc_info()[0])
    raise
else:
    print("Processing...")

ipaddr = input('Enter IP address: ')  #192.168.1.30   127.0.0.1
nm.scan(ipaddr, '22-443')  # scan host, ports from 22 to 443
nm.command_line()  # get command line used for the scan : nmap -oX - -p 22-443 127.0.0.1
nm.scaninfo()  # get nmap scan informations {'tcp': {'services': '22-443', 'method': 'connect'}}
nm.all_hosts()  # get all hosts that were scanned
nm[ipaddr].hostname()  # get one hostname for host, usualy the user record
nm[ipaddr].hostnames()  # get list of hostnames for host as a list of dict
                        # [{'name':'hostname1', 'type':'PTR'}, {'name':'hostname2', 'type':'user'}]
nm[ipaddr].hostname()  # get hostname for host
nm[ipaddr].state()  # get state of host (up|down|unknown|skipped)
nm[ipaddr].all_protocols()  # get all scanned protocols ['tcp', 'udp'] in (ip|tcp|udp|sctp)
nm[ipaddr]['tcp'].keys()  # get all ports for tcp protocol
nm[ipaddr].all_tcp()  # get all ports for tcp protocol (sorted version)
nm[ipaddr].all_udp()  # get all ports for udp protocol (sorted version)
nm[ipaddr].all_ip()  # get all ports for ip protocol (sorted version)
nm[ipaddr].all_sctp()  # get all ports for sctp protocol (sorted version)
nm[ipaddr].has_tcp(102)  # is there any information for port 80/tcp on host
nm[ipaddr]['tcp'][102]  # get info about port X in tcp on host
nm[ipaddr].tcp(102)  # get info about port X in tcp on host
nm[ipaddr]['tcp'][102]['state'] # get state of port X / tcp on host (open/close)

for host in nm.all_hosts():
    print('----------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())

    for proto in nm[host].all_protocols():
        print('----------------------------------')
        print('Protocol : %s' % proto)

        lport = sorted(nm[host][proto])
        for port in lport:
            print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
