from collections import defaultdict

from bs4 import BeautifulSoup
import requests
import pickle
import json

url = "https://whois.ipip.net/countries/IS"
response = requests.get(url).text
soup = BeautifulSoup(response, 'html.parser')
table = soup.find('table', attrs={'class': "table"})

ASNs = []
for row in table.findAll('tr'):
    cells = row.findAll('td')
    if len(cells) > 0:
        ASNs.append(cells[0].a['href'][1:])

addrs = defaultdict(lambda: defaultdict(list))
for asn in ASNs:
    url = "https://whois.ipip.net/" + asn + "#pills-ipv4"
    response = requests.get(url).text
    soup = BeautifulSoup(response, 'html.parser')
    table = soup.find_all('table', attrs={'class': "table"})
    # get table containing "IP Num"
    ipv4Table = None
    for t in table:
        if t.findAll(text="IP Num"):
            ipv4Table = t
            break
    if ipv4Table:
        for row in ipv4Table.find_all("a"):
            if row.text != "":
                addrs[asn]["ipv4"].append(row.text)
    ipv6Table = None
    for t in table:
        if t.findAll(text="IP NUMs(prefix /64)"):
            ipv6Table = t
            break
    if ipv6Table:
        for row in ipv6Table.find_all("a"):
            if row.text != "" and row.text[:2] != "AS":
                addrs[asn]["ipv6"].append(row.text)

with open('addrs.pickle', 'wb') as f:
    pickle.dump(json.loads(json.dumps(addrs)), f)

print(addrs)
