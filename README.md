# IP-scanner
IP scanners for Computer Security: Defence Against the Dark Arts course.

## File Description

### find_fingerprints.py

This is the script where we do the final comparison of fingerprints. 
The script runs through all detected ipv4 addresses with port 22 open and compares the fingerprints to the ones from ipv6.
Since there were so few IPv6 addresses reported by Masscan, they are just hardcoded here.
It uses the nmap method for getting ssh fingerprints.

### ipv6_nmap.py

This file contains the code that we used to scan IPv6 addresses while testing.

### time_socket.py

This file contains our own scanner, done with the socket library. 

The script also benchmarks its performance.

### scrape_addresses.py

The script that scrapes all IP ranges in Iceland from whois.ipip.net.

### generate_addrs.py

To work with Masscan, we had to create input text files with addresses. 
This file contains the logic that we used for selecting the actual IPv6 addresses that we scan.
The generated files are to big to include in git.

### generate_adjacent.py

This script generates 2 million addresses around every address that we detected with Masscan.
We fed the output of this script back to Masscan a few times to get more adjacent addresses.

### discovered_ssh.txt

The output of Masscan, listing all IPv4 addresses with port 22 open.

### addrs.pickle

A dict with ASN and networks, generated from scraping for convenience.
