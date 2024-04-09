import re;
from scapy.all import *

try:
    # Hide all verbose of scapy
    conf.verb = 0
    host = input ("Enter a host address: ")
    ports = [int(port) for port in input("Enter ports to scan: ").split(",")]

    # Using regex module for checking IPv4 address
    if(re.match("^(?:2[0-4]\d|25[0-5]|1?\d?\d)[.](?:2[0-4]\d|25[0-5]|1?\d?\d)[.](?:2[0-4]\d|25[0-5]|1?\d?\d)[.](?:2[0-4]\d|25[0-5]|1?\d?\d)$",host)):
        print("\n\nScanning...")
        print("Host:", host)
        print("Ports:", ports)
        
        # Using sr() function storing successful transmission and corresponding response into ans
        # and storing unanswered packets into unans (which the ports may be closed or filtered)
        # Randomize source port to avoid detection (sport=RandShort)
        # Set timeout=2 to avoid waiting infinitely
        ans,unans = sr(IP(dst=host)/TCP(sport=RandShort(), dport=ports,flags="S"), timeout=2)
        # Create a table to show open port
        # We only show port with SA flag (Syn ACK)
        print("------------- Port -------------")
        ans.filter(lambda s,r: TCP in r and r[TCP].flags&2).make_table(lambda s,r:(s.dst, s.dport, "Open"))

except (ValueError, RuntimeError, TypeError, NameError):
    print("[-] Some Error Occured")
    print("[-] Exiting..")