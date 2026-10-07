import subprocess


def run_traceroute(target):
    """
    Run traceroute against an authorized target.
    """

    command = [
        "traceroute",
        "-m", "12",
        "-w", "2",
        target
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=40
        )

        return {
            "success": result.returncode == 0,
            "target": target,
            "output": result.stdout,
            "error": result.stderr
        }

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "target": target,
            "output": "",
            "error": "Traceroute timed out."
        }

    except FileNotFoundError:

        return {
            "success": False,
            "target": target,
            "output": "",
            "error": "Traceroute is not installed."
        }

    except Exception as error:

        return {
            "success": False,
            "target": target,
            "output": "",
            "error": str(error)
        }


if __name__ == "__main__":

    print("=" * 60)
    print("NETFORGE TRACEROUTE ANALYZER")
    print("=" * 60)

    result = run_traceroute("127.0.0.1")

    if result["success"]:

        print(result["output"])

    else:

        print("ERROR:")
        print(result["error"])
