import os
from datetime import datetime


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

REPORT_DIR = os.path.join(
    PROJECT_ROOT,
    "reports"
)


def generate_report(
    target,
    assessment,
    findings=None,
    dns_result=None,
    traffic_result=None,
    traceroute_result=None
):
    findings = findings or []
    dns_result = dns_result or {}
    traffic_result = traffic_result or {}
    traceroute_result = traceroute_result or {}

    os.makedirs(
        REPORT_DIR,
        exist_ok=True
    )

    timestamp = datetime.now()

    filename = (
        "NETFORGE_Report_"
        + timestamp.strftime("%Y%m%d_%H%M%S")
        + ".html"
    )

    report_path = os.path.join(
        REPORT_DIR,
        filename
    )

    score = assessment.get(
        "score",
        0
    )

    security_level = assessment.get(
        "security_level",
        "LOW"
    )

    recommendations = assessment.get(
        "recommendations",
        []
    )

    finding_rows = ""

    for finding in findings:
        finding_rows += f"""
        <tr>
            <td>{finding.get("port", "-")}</td>
            <td>{finding.get("service", "-")}</td>
            <td>{finding.get("version", "-")}</td>
            <td>{finding.get("severity", "INFO")}</td>
            <td>{finding.get("risk", 0)}</td>
            <td>{finding.get("recommendation", "-")}</td>
        </tr>
        """

    recommendation_rows = ""

    for recommendation in recommendations:
        recommendation_rows += f"""
        <li>{recommendation}</li>
        """

    traffic_packets = traffic_result.get(
        "packet_count",
        0
    )

    dns_hostname = dns_result.get(
        "hostname",
        "-"
    )

    dns_ipv4 = ", ".join(
        dns_result.get("ipv4", [])
    ) or "-"

    dns_ipv6 = ", ".join(
        dns_result.get("ipv6", [])
    ) or "-"

    traceroute_output = traceroute_result.get(
        "output",
        ""
    )

    html = f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<title>
NETFORGE Security Assessment Report
</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #f4f6f8;
    color: #1f2937;
}}

.container {{
    max-width: 1100px;
    margin: auto;
    background: white;
    padding: 40px;
    border-radius: 12px;
}}

.header {{
    border-bottom: 3px solid #111827;
    padding-bottom: 20px;
    margin-bottom: 30px;
}}

.header h1 {{
    margin: 0;
}}

.meta {{
    margin-top: 10px;
    color: #6b7280;
}}

.summary {{
    display: flex;
    gap: 20px;
    margin: 25px 0;
}}

.card {{
    flex: 1;
    padding: 20px;
    background: #f3f4f6;
    border-radius: 10px;
}}

.card h3 {{
    margin-top: 0;
}}

.score {{
    font-size: 32px;
    font-weight: bold;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}}

th,
td {{
    border: 1px solid #d1d5db;
    padding: 10px;
    text-align: left;
    font-size: 14px;
}}

th {{
    background: #111827;
    color: white;
}}

pre {{
    background: #111827;
    color: #e5e7eb;
    padding: 20px;
    border-radius: 8px;
    overflow-x: auto;
}}

li {{
    margin-bottom: 8px;
}}

.footer {{
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid #d1d5db;
    color: #6b7280;
    font-size: 13px;
}}

</style>

</head>

<body>

<div class="container">

<div class="header">

<h1>
NETFORGE Security Assessment Report
</h1>

<div class="meta">

Target:
<strong>{target}</strong>

<br>

Generated:
<strong>
{timestamp.strftime("%Y-%m-%d %H:%M:%S")}
</strong>

</div>

</div>


<h2>Executive Summary</h2>

<p>
NETFORGE performed an authorized network security
assessment of the specified target. The assessment
combined service discovery, DNS analysis, traffic
observation and risk evaluation.
</p>


<div class="summary">

<div class="card">

<h3>Risk Score</h3>

<div class="score">
{score}/100
</div>

</div>


<div class="card">

<h3>Security Level</h3>

<div class="score">
{security_level}
</div>

</div>


<div class="card">

<h3>Findings</h3>

<div class="score">
{len(findings)}
</div>

</div>

</div>


<h2>Security Findings</h2>

<table>

<thead>

<tr>

<th>Port</th>
<th>Service</th>
<th>Version</th>
<th>Severity</th>
<th>Risk</th>
<th>Recommendation</th>

</tr>

</thead>

<tbody>

{finding_rows if finding_rows else
"<tr><td colspan='6'>No findings detected.</td></tr>"}

</tbody>

</table>


<h2>DNS Analysis</h2>

<table>

<tr>
<th>Hostname</th>
<td>{dns_hostname}</td>
</tr>

<tr>
<th>IPv4</th>
<td>{dns_ipv4}</td>
</tr>

<tr>
<th>IPv6</th>
<td>{dns_ipv6}</td>
</tr>

<tr>
<th>Status</th>
<td>{assessment.get("dns_status", "-")}</td>
</tr>

</table>


<h2>Traffic Analysis</h2>

<table>

<tr>
<th>Traffic Status</th>
<td>{assessment.get("traffic_status", "-")}</td>
</tr>

<tr>
<th>Packets Observed</th>
<td>{traffic_packets}</td>
</tr>

</table>


<h2>Traceroute</h2>

<pre>{traceroute_output or "No traceroute data available."}</pre>


<h2>Recommendations</h2>

<ul>

{recommendation_rows}

</ul>


<div class="footer">

Generated by NETFORGE —
Network Security Testing Platform

</div>

</div>

</body>

</html>
"""

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

    return {
        "success": True,
        "filename": filename,
        "path": report_path
    }


if __name__ == "__main__":

    sample_assessment = {
        "score": 5,
        "security_level": "LOW",
        "dns_status": "NORMAL",
        "traffic_status": "NORMAL",
        "recommendations": [
            "Keep detected services updated."
        ]
    }

    result = generate_report(
        target="127.0.0.1",
        assessment=sample_assessment,
        findings=[],
        dns_result={
            "hostname": "localhost",
            "ipv4": ["127.0.0.1"],
            "ipv6": ["::1"]
        },
        traffic_result={
            "packet_count": 25
        },
        traceroute_result={
            "output": "localhost"
        }
    )

    print("=" * 60)
    print("NETFORGE REPORT GENERATOR")
    print("=" * 60)
    print()
    print("Report created:")
    print(result["path"])
