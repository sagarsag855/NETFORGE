import ipaddress
import socket


def validate_target(target, mode="local"):
    """
    NETFORGE Target Authorization Policy

    Modes:
        local:
            Allows localhost and private laboratory addresses.

        external:
            Allows an explicitly authorized external target.
            The caller must explicitly provide external mode.
    """

    target = target.strip()
    mode = mode.lower().strip()

    if not target:
        return {
            "allowed": False,
            "target": target,
            "mode": mode,
            "reason": "Target cannot be empty."
        }

    if mode not in ["local", "external"]:
        return {
            "allowed": False,
            "target": target,
            "mode": mode,
            "reason": "Invalid authorization mode."
        }

    # ========================================================
    # LOCAL LAB MODE
    # ========================================================

    if mode == "local":

        allowed_names = [
            "localhost",
            "127.0.0.1",
            "::1"
        ]

        if target.lower() in allowed_names:
            return {
                "allowed": True,
                "target": target,
                "mode": "local",
                "reason": "Localhost target approved."
            }

        try:
            ip = ipaddress.ip_address(target)

            if ip.version == 4 and ip.is_private:
                return {
                    "allowed": True,
                    "target": target,
                    "mode": "local",
                    "reason": "Private IPv4 laboratory target approved."
                }

            if ip.version == 6 and ip.is_private:
                return {
                    "allowed": True,
                    "target": target,
                    "mode": "local",
                    "reason": "Private IPv6 laboratory target approved."
                }

            return {
                "allowed": False,
                "target": target,
                "mode": "local",
                "reason": (
                    "Public targets require Authorized External mode."
                )
            }

        except ValueError:
            pass

        try:
            addresses = socket.getaddrinfo(
                target,
                None
            )

            resolved_ips = set()

            for address in addresses:
                resolved_ips.add(address[4][0])

            if not resolved_ips:
                return {
                    "allowed": False,
                    "target": target,
                    "mode": "local",
                    "reason": "Target could not be resolved."
                }

            for address in resolved_ips:

                ip = ipaddress.ip_address(address)

                if ip.is_loopback:
                    continue

                if ip.is_private:
                    continue

                return {
                    "allowed": False,
                    "target": target,
                    "mode": "local",
                    "reason": (
                        "Target resolves to a public address. "
                        "Use Authorized External mode."
                    )
                }

            return {
                "allowed": True,
                "target": target,
                "mode": "local",
                "reason": "Private laboratory hostname approved."
            }

        except Exception as error:

            return {
                "allowed": False,
                "target": target,
                "mode": "local",
                "reason": f"Target validation failed: {error}"
            }

    # ========================================================
    # AUTHORIZED EXTERNAL MODE
    # ========================================================

    if mode == "external":

        return {
            "allowed": True,
            "target": target,
            "mode": "external",
            "reason": (
                "External target accepted under "
                "Authorized External mode."
            )
        }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("NETFORGE TARGET AUTHORIZATION POLICY")
    print("=" * 60)

    tests = [
        ("127.0.0.1", "local"),
        ("192.168.1.10", "local"),
        ("8.8.8.8", "local"),
        ("8.8.8.8", "external")
    ]

    for target, mode in tests:

        result = validate_target(
            target,
            mode
        )

        status = (
            "ALLOWED"
            if result["allowed"]
            else "BLOCKED"
        )

        print()
        print("Target :", target)
        print("Mode   :", mode)
        print("Status :", status)
        print("Reason :", result["reason"])
