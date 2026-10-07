import socket


def analyze_dns(target):
    result = {
        "target": target,
        "hostname": None,
        "ipv4": [],
        "ipv6": [],
        "error": None
    }

    try:
        result["hostname"] = socket.getfqdn(target)

        addresses = socket.getaddrinfo(
            target,
            None
        )

        for address in addresses:

            ip = address[4][0]

            if ":" in ip:
                if ip not in result["ipv6"]:
                    result["ipv6"].append(ip)

            else:
                if ip not in result["ipv4"]:
                    result["ipv4"].append(ip)

    except socket.gaierror as error:

        result["error"] = str(error)

    except Exception as error:

        result["error"] = str(error)

    return result


if __name__ == "__main__":

    print("=" * 60)
    print("NETFORGE DNS ANALYZER")
    print("=" * 60)

    result = analyze_dns("localhost")

    print("Hostname:", result["hostname"])
    print("IPv4:", result["ipv4"])
    print("IPv6:", result["ipv6"])

    if result["error"]:
        print("Error:", result["error"])
