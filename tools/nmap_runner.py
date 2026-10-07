import subprocess


def run_nmap(target):
    """
    Run a basic Nmap service-detection scan
    against an authorized target.
    """

    command = [
        "nmap",
        "-sV",
        "--host-timeout", "30s",
        target
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60
        )

        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "output": "",
            "error": "Nmap scan timed out."
        }

    except FileNotFoundError:
        return {
            "success": False,
            "output": "",
            "error": "Nmap is not installed or not in PATH."
        }


if __name__ == "__main__":
    result = run_nmap("127.0.0.1")

    print("=" * 60)
    print("NETFORGE NMAP SCANNER")
    print("=" * 60)

    if result["success"]:
        print(result["output"])
    else:
        print("ERROR:")
        print(result["error"])
