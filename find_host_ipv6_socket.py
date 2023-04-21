import socket

import socket
import ipaddress
from collections import defaultdict

import requests
import pickle
import asyncio
import nmap
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
import time
import paramiko


def scan_ip(ip):
    try:
        socket.gethostbyaddr(str(ip))
    except socket.herror:
        return False, None
    except socket.gaierror:
        return False, None

    client = paramiko.SSHClient()
    try:
        client.connect(ip)
    except Exception:
        return True, None
    key = client.get_transport().get_remote_server_key().get_base64()
    client.close()
    return True, key

def print_result(ip, present, fingerprint):
    if present:
        print(f"Host {ip} is present")
        if fingerprint:
            print(f"Host {ip} has fingerprint {fingerprint}")

def scan_asn(asn, ips):
    with ThreadPoolExecutor(max_workers=1000) as executor:
        def scan_and_result(type, ip):
            res = scan_ip(ip)
            if res is None:
                return None
            present, fingerprint = res
            return type, ip, present, fingerprint
        futs = []
        # if "ipv4" in ips:
        #     for ipv4 in ips["ipv4"]:
        #         net = ipaddress.IPv4Network(ipv4)
        #         for ip in net:
        #             futs.append(executor.submit(scan_and_result, "ipv4", ip))

        if "ipv6" in ips:
            for ipv6 in ips["ipv6"]:
                net = ipaddress.IPv6Network(ipv6)
                num = 0
                for ip in net:
                    num += 1
                    futs.append(executor.submit(scan_and_result, "ipv6", ip))
                    if num > 1000:
                        break

        for result in concurrent.futures.as_completed(futs):
            result = result.result()
            if result is None:
                continue
            type, ip, present, fingerprint = result
            print_result(ip, present, fingerprint)
            yield type, ip, present, fingerprint

        print(f"IPv6 scan for {asn} done")

def main():
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

    # we're gonna keep a running average
    start_time = time.time()
    number = 0
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
            end = time.time()
            number += 1
            print(f"Average time: {(end - start_time) / number}")
        #with open('fingerprints.pickle', 'wb') as f:
        #    pickle.dump((asn, fingerprints, presence), f)


def find_fingerprints():
    # print("starting")
    # sshs = []
    # with open("discovered_ssh.txt", "r") as f:
    #     for line in f:
    #         sshs.append(line[32:].strip())
    # fingerprints_v4 = defaultdict(list)
    # for i, ip in enumerate(sshs):
    #     fingerprint = scan_ip(ip)
    #     print(i / len(sshs) * 100, "%")
    #     if fingerprint:
    #         fingerprints_v4[fingerprint].append(ip)
    #         with open("fingerprints_v4.pickle", "wb") as f:
    #             pickle.dump(fingerprints_v4, f)
    with open("fingerprints_v4.pickle", "rb") as f:
        fingerprints_v4 = pickle.load(f)
        print(fingerprints_v4)
    print("finished taking fingerprints")
    for ip in ["2a07:54c3::7", "2a07:54c3::1", "2a0a:89c0::1", "2a01:8280:dc00::7b", "2a01:8280:dc00::77", "2a01:8280:dc00::7a", "2a01:8280:dc00::75", "2a01:8280:dc00::78", "2a01:8280:dc00::79", "2a01:8280:dc00::76"]:
        fingerprint = scan_ip(ip)
        if fingerprint:
            if fingerprint in fingerprints_v4:
                print(f"match! {ip}, {fingerprints_v4[fingerprint]}")


if __name__ == "__main__":
    main()
