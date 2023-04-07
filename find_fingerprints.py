import socket

import socket
import ipaddress
from collections import defaultdict

import paramiko
import requests
import pickle
import asyncio
import nmap


def scan_ip(ip):
    try:
        nm = nmap.PortScanner()
        res = nm.scan(hosts=ip, arguments="-p 22 -6 -script ssh-hostkey")
        print(res["scan"][ip]["tcp"][22]["script"]["ssh-hostkey"])
        return res["scan"][ip]["tcp"][22]["script"]["ssh-hostkey"]
    except Exception:
        return None


def scan_asn(asn, ips):
    print("test")
    should_fail = scan_ip("2001:4860:4860::1234")
    if not should_fail[0]:
        print("nnot found")
    make_sure = scan_ip("2001:4860:4860::8888")
    if make_sure[0]:
        print("found")
    if "ipv4" in ips:
        for ipv4 in ips["ipv4"]:
            net = ipaddress.IPv4Network(ipv4)
            for ip in net:
                present, fingerprint = scan_ip(ip)
                if present:
                    print(f"Host {ip} is present")
                    if fingerprint:
                        print(f"Host {ip} has fingerprint {fingerprint}")
                if present:
                    yield "ipv4", ip, present, fingerprint
    print(f"IPv4 scan for {asn} done")
    if "ipv6" in ips:
        for ipv6 in ips["ipv6"]:
            net = ipaddress.IPv6Network(ipv6)
            for ip, present, fingerprint in scan_ipv6_net(net):
                if present:
                    print(f"Host {ip} is present")
                    if fingerprint:
                        print(f"Host {ip} has fingerprint {fingerprint}")
                    yield "ipv4", ip, present, fingerprint



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
    find_fingerprints()
