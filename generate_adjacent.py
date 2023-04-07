import ipaddress

def generate_adjacent(f, ip: str):
    ip = ipaddress.ip_address(ip)
    for i in range(-1000000, 1000000):
        f.write(str(ip + i) + "\n")

if __name__ == "__main__":
    with open("adjacent.txt", "w") as f:
        for ip in ["2a07:54c3::7", "2a0a:89c0::1", "2a01:8280:dc00::1", "2a07:54c3::7", "2a07:54c3::1", "2a0a:89c0::1", "2a01:8280:dc00::1"]:
            generate_adjacent(f, ip)