def analyze_nmap_output(nmap_output):
    findings = []

    lines = nmap_output.splitlines()

    for line in lines:
        if "/tcp" not in line or "open" not in line:
            continue

        parts = line.split()

        if len(parts) < 3:
            continue

        port = parts[0]
        service = parts[2]
        version = " ".join(parts[3:]) if len(parts) > 3 else "Unknown"

        finding = {
            "port": port,
            "service": service,
            "version": version,
            "severity": "INFO",
            "risk": 10,
            "recommendation": "Review whether this service is required."
        }

        if service == "ssh":
            finding["severity"] = "LOW"
            finding["risk"] = 20
            finding["recommendation"] = (
                "Keep SSH updated, disable unnecessary access, "
                "and use strong authentication."
            )

        elif service in ["ftp", "telnet"]:
            finding["severity"] = "HIGH"
            finding["risk"] = 70
            finding["recommendation"] = (
                "Avoid insecure plaintext protocols where possible. "
                "Use secure alternatives."
            )

        findings.append(finding)

    return findings
