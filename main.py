import socket
import ipaddress
import nmap
from collections import defaultdict

import paramiko
import requests
import pickle
import asyncio
import time

def scan_ipv6_range_nmap(ip):
    print("Starting IP: " + str(ip))
    ip = ipaddress.IPv6Address(ip)
    nm = nmap.PortScanner()
    result = nm.scan(hosts=str(ip), ports='443', arguments='-nP -6')
    if result['scan']:
        print("IPv6 found!: " + str(ip))
        print("Addresses: ", result['scan'][str(ip)]['addresses'])
        range_step = 1000000  # to be adjusted
        ipv6_found = True
        range_up = ip
        current_up = ip + 1
        while ipv6_found:
            ipv6_found = False
            range_up += range_step
            while current_up < range_up:
                print("Current up: " + str(current_up))
                result_up = nm.scan(hosts=str(current_up), ports='443', arguments='-nP -6')
                if result_up['scan']:
                    print("IPv6 found in the range!: ", result_up)
                    print("Addresses: ", result_up['scan'][str(ip)]['addresses'])
                    ipv6_found = True
                current_up += 1
        ipv6_found = True
        range_down = ip
        current_down = ip - 1
        while ipv6_found:
            ipv6_found = False
            range_down -= range_step
            while current_down > range_down:
                print("Current down: " + str(current_down))
                result_down = nm.scan(hosts=str(current_down), ports='443', arguments='-nP -6')
                if result_down['scan']:
                    print("IPv6 found in the lower range!: ", result_down)
                    print("Addresses: ", result_down['scan'][str(ip)]['addresses'])
                    ipv6_found = True
                current_down -= 1
        current = current_up
        # TODO

def main():
    scan_ipv6_range_nmap("2a01:9460::1")
    scan_ipv6_range_nmap("2a0a:89c0::1")
    scan_ipv6_range_nmap("2a01:8280:dc00::1")

if __name__ == "__main__":
    main()
