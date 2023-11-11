import pyfiglet
import argparse
import socket
import sys
from datetime import datetime

ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
print(ascii_banner)

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="Target IP Address\nExample: python3 port_scanner.py -t 10.0.1.7\nor, python3 arp_spoofer.py -t www.google.com")
    parser.add_argument("-p","--port",dest="port",help="Maximum Port Range\nExample: python3 port_scanner.py -t 10.0.1.7 -p 1023\nor, python3 arp_spoofer.py -t www.google.com -p 1023")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target's IP address or Hostname, use --help for more info.")
    if not options.port:
        parser.error("[-] Please specify a maximum port scanning range, use --help for more info.")
        
    target = socket.gethostbyname(options.target)
    return target, int(options.port)


target_ip, max_port_range = get_arguments()
print("-" * 50)
print("Scanning Target: " + target_ip)
print("Scanning Started At: " + str(datetime.now()))
print("-" * 50)

try:
    for port in range(1, max_port_range+1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.1)
        is_open = s.connect_ex((target_ip, port))
        if is_open == 0:
            print("Port {} is open".format(port))
        s.close()
except KeyboardInterrupt:
    print("\n\nExiting Program!!!")
    sys.exit()
except socket.gaierror:
    print("\n\nHostname couldn't be resolved!!!")
    sys.exit()
except socket.error:
    print("\n\nServer not responding!!!")
    sys.exit()

