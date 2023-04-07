import ipaddress
import pickle

def generate_addrs(net: str) -> str:
    net = ipaddress.ip_network(net)
    mask = (128 - 64 - net.prefixlen - 17)
    step = 1 << (mask if mask > 0 else 0)
    for i in range(0, 1 << (mask if mask > 0 else 0)):
        yield str(net.network_address + (i * step) + 0x22)

if __name__ == "__main__":
    with open("addrs.pickle", "rb") as f:
        addrs = pickle.load(f)

    with open("net.txt", "w") as f:
        for asn, ips in addrs.items():
            if "ipv6" in ips:
                for ipv6net in ips["ipv6"]:
                    for addr in generate_addrs(ipv6net):
                        f.write(addr + "\n")