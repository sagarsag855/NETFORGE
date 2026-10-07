import subprocess
import re


def get_interfaces():
    """
    Get available network interfaces using TShark.
    """

    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return {
                "success": False,
                "interfaces": [],
                "error": result.stderr.strip()
            }

        interfaces = []

        for line in result.stdout.splitlines():

            line = line.strip()

            if not line:
                continue

            match = re.match(r"(\d+)\.\s+(.+)", line)

            if match:
                interfaces.append({
                    "id": match.group(1),
                    "name": match.group(2)
                })

        return {
            "success": True,
            "interfaces": interfaces,
            "error": None
        }

    except FileNotFoundError:

        return {
            "success": False,
            "interfaces": [],
            "error": "TShark is not installed."
        }

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "interfaces": [],
            "error": "TShark interface detection timed out."
        }

    except Exception as error:

        return {
            "success": False,
            "interfaces": [],
            "error": str(error)
        }


def capture_traffic(interface="any", duration=10):
    """
    Capture traffic from an authorized local/lab interface.

    The capture is limited by time and packet count.
    """

    command = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{duration}",
        "-c", "100",
        "-T", "fields",
        "-E", "separator=|",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport"
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=duration + 15
        )

        if result.returncode != 0:

            return {
                "success": False,
                "packets": [],
                "error": result.stderr.strip()
            }

        packets = []

        for line in result.stdout.splitlines():

            fields = line.split("|")

            while len(fields) < 8:
                fields.append("")

            packet = {
                "number": fields[0],
                "source": fields[1] or "-",
                "destination": fields[2] or "-",
                "protocol": fields[3] or "-",
                "tcp_source_port": fields[4] or "-",
                "tcp_destination_port": fields[5] or "-",
                "udp_source_port": fields[6] or "-",
                "udp_destination_port": fields[7] or "-"
            }

            packets.append(packet)

        return {
            "success": True,
            "interface": interface,
            "duration": duration,
            "packet_count": len(packets),
            "packets": packets,
            "error": None
        }

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "packets": [],
            "error": "Traffic capture timed out."
        }

    except FileNotFoundError:

        return {
            "success": False,
            "packets": [],
            "error": "TShark is not installed."
        }

    except Exception as error:

        return {
            "success": False,
            "packets": [],
            "error": str(error)
        }


if __name__ == "__main__":

    print("=" * 60)
    print("NETFORGE TSHARK TRAFFIC ANALYZER")
    print("=" * 60)

    print("\nAvailable interfaces:\n")

    interfaces = get_interfaces()

    if not interfaces["success"]:

        print("ERROR:")
        print(interfaces["error"])

        raise SystemExit(1)

    for interface in interfaces["interfaces"]:
        print(
            f'{interface["id"]}. '
            f'{interface["name"]}'
        )

    print("\nStarting local traffic capture...")
    print("Duration: 10 seconds")
    print("Maximum packets: 100")

    result = capture_traffic(
        interface="any",
        duration=10
    )

    if not result["success"]:

        print("\nERROR:")
        print(result["error"])

        raise SystemExit(1)

    print("\nCapture completed.")
    print("Interface:", result["interface"])
    print("Packets captured:", result["packet_count"])

    print("\n" + "=" * 60)
    print("PACKET SUMMARY")
    print("=" * 60)

    for packet in result["packets"][:20]:

        print(
            f'{packet["number"]:>4} | '
            f'{packet["source"]:<18} | '
            f'{packet["destination"]:<18} | '
            f'{packet["protocol"]}'
        )
