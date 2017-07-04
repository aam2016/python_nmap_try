import sys
import os

import nmap


# print(nmap.__version__)
# try:
#     nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
# except nmap.PortScannerError:
#     print('Nmap not found', sys.exc_info()[0])
#     sys.exit(0)
# except:
#     print("Unexpected error:", sys.exc_info()[0])


nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
nm.scan('127.0.0.1', '22-443')  # scan host 127.0.0.1, ports from 22 to 443
nm.command_line()  # get command line used for the scan : nmap -oX - -p 22-443 127.0.0.1
nm.scaninfo()  # get nmap scan information {'tcp': {'services': '22-443', 'method': 'connect'}}
nm.all_hosts()   # get all hosts that were scanned
for host in nm.all_hosts():
    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())

    for proto in nm[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)

        lport = nm[host][proto].keys()
        lport.sort()
        for port in lport:
            print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
