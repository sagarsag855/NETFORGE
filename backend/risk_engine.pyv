def calculate_risk(findings=None, dns_result=None, traffic_result=None):
    """
    NETFORGE Advanced Risk Scoring Engine.

    Calculates a defensive risk score from:
    - Nmap service findings
    - DNS analysis
    - Traffic capture observations
    """

    findings = findings or {}
    dns_result = dns_result or {}
    traffic_result = traffic_result or {}

    score = 0
    factors = []

    # ========================================================
    # NMAP FINDINGS
    # ========================================================

    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0

    if isinstance(findings, list):

        for finding in findings:

            severity = str(
                finding.get("severity", "INFO")
            ).upper()

            if severity == "HIGH":

                high_count += 1
                score += 25

                factors.append(
                    "High-risk network service detected."
                )

            elif severity == "MEDIUM":

                medium_count += 1
                score += 15

                factors.append(
                    "Medium-risk network service detected."
                )

            elif severity == "LOW":

                low_count += 1
                score += 5

                factors.append(
                    "Low-risk network service detected."
                )

            else:

                info_count += 1

    # ========================================================
    # DNS ANALYSIS
    # ========================================================

    dns_status = "NORMAL"

    if isinstance(dns_result, dict):

        if dns_result.get("error"):

            dns_status = "ERROR"

            score += 5

            factors.append(
                "DNS resolution returned an error."
            )

        else:

            ipv4 = dns_result.get(
                "ipv4",
                []
            )

            ipv6 = dns_result.get(
                "ipv6",
                []
            )

            if not ipv4 and not ipv6:

                dns_status = "NO ADDRESS"

                score += 5

                factors.append(
                    "No resolved IP address was detected."
                )

    # ========================================================
    # TRAFFIC ANALYSIS
    # ========================================================

    traffic_status = "NORMAL"

    packet_count = 0

    if isinstance(traffic_result, dict):

        packet_count = traffic_result.get(
            "packet_count",
            0
        )

        try:
            packet_count = int(packet_count)
        except (ValueError, TypeError):
            packet_count = 0

        if traffic_result.get("success"):

            if packet_count == 0:

                traffic_status = "NO TRAFFIC"

            elif packet_count >= 100:

                traffic_status = "HIGH ACTIVITY"

                score += 5

                factors.append(
                    "High packet activity was observed "
                    "during the capture window."
                )

            else:

                traffic_status = "NORMAL"

    # ========================================================
    # SCORE LIMIT
    # ========================================================

    score = min(
        max(score, 0),
        100
    )

    # ========================================================
    # SECURITY LEVEL
    # ========================================================

    if score >= 75:

        security_level = "CRITICAL"

    elif score >= 50:

        security_level = "HIGH"

    elif score >= 25:

        security_level = "MEDIUM"

    else:

        security_level = "LOW"

    # ========================================================
    # RECOMMENDATIONS
    # ========================================================

    recommendations = []

    if high_count > 0:

        recommendations.append(
            "Review and restrict high-risk network services."
        )

    if medium_count > 0:

        recommendations.append(
            "Review medium-risk services and "
            "disable unnecessary exposure."
        )

    if low_count > 0:

        recommendations.append(
            "Keep detected services updated "
            "and monitor their exposure."
        )

    if dns_status == "ERROR":

        recommendations.append(
            "Investigate DNS resolution problems."
        )

    if traffic_status == "HIGH ACTIVITY":

        recommendations.append(
            "Review traffic patterns and "
            "investigate unexpected activity."
        )

    if not recommendations:

        recommendations.append(
            "No major security concerns were detected "
            "during this assessment."
        )

    # Remove duplicate factors

    factors = list(
        dict.fromkeys(factors)
    )

    return {

        "score": score,

        "security_level":
            security_level,

        "high_count":
            high_count,

        "medium_count":
            medium_count,

        "low_count":
            low_count,

        "info_count":
            info_count,

        "dns_status":
            dns_status,

        "traffic_status":
            traffic_status,

        "packet_count":
            packet_count,

        "factors":
            factors,

        "recommendations":
            recommendations

    }


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    sample_findings = [

        {
            "port": "22/tcp",
            "service": "ssh",
            "severity": "LOW",
            "risk": 20
        }

    ]

    sample_dns = {

        "error": None,
        "ipv4": [
            "127.0.0.1"
        ],
        "ipv6": []

    }

    sample_traffic = {

        "success": True,
        "packet_count": 25

    }

    result = calculate_risk(
        findings=sample_findings,
        dns_result=sample_dns,
        traffic_result=sample_traffic
    )

    print("=" * 60)
    print("NETFORGE ADVANCED RISK ENGINE")
    print("=" * 60)

    print(
        "\nRisk Score:",
        result["score"]
    )

    print(
        "Security Level:",
        result["security_level"]
    )

    print(
        "High Risk:",
        result["high_count"]
    )

    print(
        "Medium Risk:",
        result["medium_count"]
    )

    print(
        "Low Risk:",
        result["low_count"]
    )

    print(
        "DNS Status:",
        result["dns_status"]
    )

    print(
        "Traffic Status:",
        result["traffic_status"]
    )

    print(
        "Packets:",
        result["packet_count"]
    )

    print("\nRecommendations:")

    for recommendation in result[
        "recommendations"
    ]:

        print(
            "-",
            recommendation
        )
