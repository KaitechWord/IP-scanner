import socket
import ipaddress
import nmap
from collections import defaultdict

import paramiko
import requests
import pickle
import asyncio
import time


def scan_ipv6_range(ip):
    print("range")
    result = scan_ip(ip)
    yield (result[0], ip, *result[1:3])
    if result[1]:
        print("IPv6 found!: " + str(ip))
        range_step = 2 ** 10  # needs to be adjusted
        ipv6_found = True
        range_up = ip
        current_up = ip + 1
        while ipv6_found:
            ipv6_found = False
            range_up += range_step
            while current_up < ip + range_up:
                result_up = scan_ip(current_up)
                if result_up[1]:
                    yield (result[0], current_up, *result_up[1:3])
                    ipv6_found = True
                current_up += 1
        ipv6_found = True
        range_down = ip
        current_down = ip - 1
        while ipv6_found:
            ipv6_found = False
            range_down -= range_step
            while current_up > ip - range_down:
                result_down = scan_ip(current_down)
                if result_down[0]:
                    yield (result[0], current_down, *result_down[1:3])
                    ipv6_found = True
                current_up -= 1
        current = current_up
        # TODO


def scan_ipv6_range_nmap(ip):
    print("range")
    nm = nmap.PortScanner()
    result = nm.scan(hosts=str(ip), ports='443')
    print(result)
    if result[1]:
        print("IPv6 found!: " + str(ip))
        range_step = 2 ** 10  # needs to be adjusted
        ipv6_found = True
        range_up = ip
        current_up = ip + 1
        while ipv6_found:
            ipv6_found = False
            range_up += range_step
            while current_up < ip + range_up:
                result_up = scan_ip(current_up)
                if result_up[1]:
                    yield (result[0], current_up, *result_up[1:3])
                    ipv6_found = True
                current_up += 1
        ipv6_found = True
        range_down = ip
        current_down = ip - 1
        while ipv6_found:
            ipv6_found = False
            range_down -= range_step
            while current_up > ip - range_down:
                result_down = scan_ip(current_down)
                if result_down[0]:
                    yield (result[0], current_down, *result_down[1:3])
                    ipv6_found = True
                current_up -= 1
        current = current_up
        # TODO


def scan_ip(ip):
    print(str(ip))
    start = time.time()
    try:
        socket.gethostbyaddr(str(ip))
    except socket.herror:
        end = time.time()
        print("Time: ", end - start)
        endTime = end - start
        return endTime, False, None
    except socket.gaierror:

        end = time.time()
        print("Time: ", end - start)
        endTime = end - start
        return endTime, False, None

    client = paramiko.SSHClient()
    try:
        client.connect(ip)
        end = time.time()
        print("Time: ", end - start)
        endTime = end - start
    except Exception:
        end = time.time()
        endTime = end - start
        return endTime, True, None
    client.close()
    return endTime, True, client.get_transport().get_remote_server_key().get_base64()


def scan_ipv6_net(net: ipaddress.IPv6Network):
    print("ipv6 scanning started")
    size = net.num_addresses
    print("size: ", size)
    start = net.network_address
    step = size >> 8 if size < 2 ** 24 else 2 ** 16
    current = start
    while current < start + size:
        result = scan_ip(current)
        yield (result[0], current, *result[1:3])
        if result[1]:
            print("IPv6 found!: " + current)
            range_step = 2 ** 10  # needs to be adjusted
            ipv6_found = True
            range_up = current
            current_up = current + 1
            while ipv6_found:
                ipv6_found = False
                range_up += range_step
                while current_up < range_step:
                    result_up = scan_ip(current_up)
                    if result_up[1]:
                        yield (result[0], current_up, *result_up[1:3])
                        ipv6_found = True
                    current_up += 1
            ipv6_found = True
            range_down = current
            current_down = current - 1
            while ipv6_found:
                ipv6_found = False
                range_down -= range_step
                while current_up > range_step:
                    result_down = scan_ip(current_down)
                    if result_down[0]:
                        yield (result[0], current_down, *result_down[1:3])
                        ipv6_found = True
                    current_up -= 1
            current = current_up
            # TODO

        current += step
    print("ipv6 scanning ended")


def scan_asn(asn, ips):
    found_time = 0.0
    notfound_time = 0.0
    counter_found = 1
    counter_notfound = 0
    if "ipv4" in ips:
        for ipv4 in ips["ipv4"]:
            net = ipaddress.IPv4Network(ipv4)
            for ip in net:
                endTime, present, fingerprint = scan_ip(ip)
                if present:
                    print(f"Host {ip} is present")
                    found_time += endTime
                    counter_found += 1
                    if fingerprint:
                        print(f"Host {ip} has fingerprint {fingerprint}")
                else:
                    notfound_time += endTime
                    counter_notfound += 1
                if present:
                    yield "ipv4", ip, present, fingerprint
    print("Found time: ", found_time/counter_found)
    print("NotFound time: ", notfound_time/counter_notfound)
    print(f"IPv4 scan for {asn} done")
    found_time = 0.0
    notfound_time = 0.0
    counter_found = 1
    counter_notfound = 0
    counter = 0
    if "ipv6" in ips:
        for ipv6 in ips["ipv6"]:
            net = ipaddress.IPv6Network(ipv6)
            for endTime, ip, present, fingerprint in scan_ipv6_net(net):
                if present:
                    found_time += endTime
                    counter_found += 1
                    print(f"Host {ip} is present")
                    if fingerprint:
                        print(f"Host {ip} has fingerprint {fingerprint}")
                    yield "ipv4", ip, present, fingerprint
                else:
                    notfound_time += endTime
                    counter_notfound += 1
                counter += 1
                if counter == 100:
                    print("Found time: ", found_time / counter_found)
                    print("NotFound time: ", notfound_time / counter_notfound)
                    quit()


def main():
    print("?!?!?!?!?!")
    result = scan_ipv6_range(ipaddress.ip_address("2a01:9460::1"))
    print(list(result))
    result = scan_ipv6_range(ipaddress.ip_address("2a0a:89c0::1"))
    print(list(result))
    result = scan_ipv6_range(ipaddress.ip_address("2a01:8280:dc00::1"))
    print(list(result))
    print("slychacmnie")
    with open('addrs.pickle', 'rb') as f:
        addrs = pickle.load(f)
    try:
        with open("fingerprints.pickle", 'rb') as f:
            asn_last, fingerprints, presence = pickle.load(f)
    except FileNotFoundError:
        fingerprints = {"ipv4": defaultdict(list), "ipv6": defaultdict(list)}
        presence = {"ipv4": [], "ipv6": []}
        asn_last = None

    last_found = asn_last is None

    for asn, ips in addrs.items():
        if not last_found:
            if asn == asn_last:
                last_found = True
            continue
        for type, ip, present, fingerprint in scan_asn(asn, ips):
            if fingerprint:
                fingerprints[type][fingerprint].append(ip)
            if present:
                presence[type].append(ip)
        with open('fingerprints.pickle', 'wb') as f:
            pickle.dump((asn, fingerprints, presence), f)


if __name__ == "__main__":
    main()
