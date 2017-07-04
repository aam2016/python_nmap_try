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
    print("Ok...")

nm.scan('127.0.0.1', '01-1000')  # scan host 127.0.0.1, ports from 01 to 1000
nm.command_line()  # get command line used for the scan : nmap -oX - -p 22-443 127.0.0.1
nm.scaninfo()  # get nmap scan information {'tcp': {'services': '22-443', 'method': 'connect'}}
nm.all_hosts()   # get all hosts that were scanned
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
