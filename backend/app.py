import sys
import os

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, jsonify, request, send_from_directory

from tools.nmap_runner import run_nmap
from backend.analyzer import analyze_nmap_output
from backend.dns import analyze_dns
from backend.network import run_traceroute
from backend.traffic import get_interfaces, capture_traffic
from backend.risk_engine import calculate_risk
from backend.target_policy import validate_target

from database.database import (
    initialize_database,
    save_scan,
    get_scan_history,
    get_scan
)

from backend.reporter import generate_report


app = Flask(__name__)

initialize_database()


# ============================================================
# TARGET AUTHORIZATION
# ============================================================

def authorize_target(target, mode="local"):

    result = validate_target(
        target,
        mode
    )

    if not result["allowed"]:

        return jsonify({
            "success": False,
            "authorized": False,
            "mode": mode,
            "target": target,
            "error": result["reason"]
        }), 403

    return None


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return jsonify({
        "project": "NETFORGE",
        "status": "online",
        "mode": "AUTHORIZED LAB MODE",
        "message": "Network Security Testing Platform"
    })


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    return send_from_directory(
        os.path.join(
            PROJECT_ROOT,
            "frontend"
        ),
        "dashboard.html"
    )


# ============================================================
# POLICY
# ============================================================

@app.route("/api/policy", methods=["GET"])
def policy_status():

    return jsonify({
        "success": True,
        "modes": {
            "local": {
                "name": "Local Lab",
                "description": (
                    "localhost and private laboratory targets"
                )
            },
            "external": {
                "name": "Authorized External",
                "description": (
                    "Public targets that you are explicitly "
                    "authorized to assess"
                )
            }
        }
    })


# ============================================================
# NMAP SCAN
# ============================================================

@app.route("/api/scan", methods=["POST"])
def scan():

    data = request.get_json() or {}

    target = data.get(
        "target",
        ""
    ).strip()

    mode = data.get(
        "mode",
        "local"
    ).strip().lower()

    if not target:

        return jsonify({
            "success": False,
            "error": "Target is required"
        }), 400

    if mode not in ["local", "external"]:

        return jsonify({
            "success": False,
            "error": "Invalid authorization mode."
        }), 400

    authorization_error = authorize_target(
        target,
        mode
    )

    if authorization_error:
        return authorization_error

    result = run_nmap(target)

    if not result["success"]:

        return jsonify(result)

    findings = analyze_nmap_output(
        result["output"]
    )

    if findings:

        risk_score = round(
            sum(
                item["risk"]
                for item in findings
            ) / len(findings)
        )

    else:

        risk_score = 0

    return jsonify({
        "success": True,
        "authorized": True,
        "mode": mode,
        "target": target,
        "nmap_output": result["output"],
        "findings": findings,
        "risk_score": risk_score
    })


# ============================================================
# DNS
# ============================================================

@app.route("/api/dns", methods=["POST"])
def dns_scan():

    data = request.get_json() or {}

    target = data.get(
        "target",
        ""
    ).strip()

    mode = data.get(
        "mode",
        "local"
    ).strip().lower()

    if not target:

        return jsonify({
            "success": False,
            "error": "Target is required"
        }), 400

    authorization_error = authorize_target(
        target,
        mode
    )

    if authorization_error:
        return authorization_error

    result = analyze_dns(target)

    return jsonify({
        "success": result["error"] is None,
        "authorized": True,
        "mode": mode,
        "dns": result
    })


# ============================================================
# TRACEROUTE
# ============================================================

@app.route("/api/traceroute", methods=["POST"])
def traceroute_scan():

    data = request.get_json() or {}

    target = data.get(
        "target",
        ""
    ).strip()

    mode = data.get(
        "mode",
        "local"
    ).strip().lower()

    if not target:

        return jsonify({
            "success": False,
            "error": "Target is required"
        }), 400

    authorization_error = authorize_target(
        target,
        mode
    )

    if authorization_error:
        return authorization_error

    result = run_traceroute(target)

    return jsonify({
        **result,
        "authorized": True,
        "mode": mode
    })


# ============================================================
# TRAFFIC INTERFACES
# ============================================================

@app.route("/api/traffic/interfaces", methods=["GET"])
def traffic_interfaces():

    return jsonify(
        get_interfaces()
    )


# ============================================================
# TRAFFIC CAPTURE
# ============================================================

@app.route("/api/traffic", methods=["POST"])
def traffic_scan():

    data = request.get_json() or {}

    interface = data.get(
        "interface",
        "any"
    )

    duration = data.get(
        "duration",
        10
    )

    try:

        duration = int(duration)

    except (ValueError, TypeError):

        duration = 10

    duration = max(
        1,
        min(duration, 30)
    )

    return jsonify(
        capture_traffic(
            interface=interface,
            duration=duration
        )
    )


# ============================================================
# RISK ASSESSMENT
# ============================================================

@app.route("/api/risk", methods=["POST"])
def risk_assessment():

    data = request.get_json() or {}

    target = data.get(
        "target",
        "Unknown"
    )

    mode = data.get(
        "mode",
        "local"
    ).strip().lower()

    authorization_error = authorize_target(
        target,
        mode
    )

    if authorization_error:
        return authorization_error

    findings = data.get(
        "findings",
        []
    )

    dns_result = data.get(
        "dns",
        {}
    )

    traffic_result = data.get(
        "traffic",
        {}
    )

    assessment = calculate_risk(
        findings=findings,
        dns_result=dns_result,
        traffic_result=traffic_result
    )

    scan_id = save_scan(
        target=target,
        assessment=assessment
    )

    return jsonify({
        "success": True,
        "authorized": True,
        "mode": mode,
        "scan_id": scan_id,
        "assessment": assessment
    })


# ============================================================
# HISTORY
# ============================================================

@app.route("/api/history", methods=["GET"])
def scan_history():

    return jsonify({
        "success": True,
        "scans": get_scan_history()
    })


@app.route("/api/history/<int:scan_id>", methods=["GET"])
def single_scan(scan_id):

    scan = get_scan(scan_id)

    if scan is None:

        return jsonify({
            "success": False,
            "error": "Scan not found."
        }), 404

    return jsonify({
        "success": True,
        "scan": scan
    })


# ============================================================
# ANALYTICS
# ============================================================

@app.route("/api/analytics", methods=["GET"])
def analytics():

    history = get_scan_history()

    total_scans = len(history)

    if total_scans == 0:

        return jsonify({
            "success": True,
            "analytics": {
                "total_scans": 0,
                "unique_targets": 0,
                "high_risk_scans": 0,
                "average_risk": 0,
                "risk_history": [],
                "severity_distribution": {
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFO": 0
                }
            }
        })

    unique_targets = len(
        set(
            scan["target"]
            for scan in history
        )
    )

    high_risk_scans = sum(
        1
        for scan in history
        if scan["security_level"]
        in ["HIGH", "CRITICAL"]
    )

    total_risk = sum(
        scan["risk_score"]
        for scan in history
    )

    average_risk = round(
        total_risk / total_scans
    )

    severity_distribution = {
        "HIGH": sum(
            scan["high_count"]
            for scan in history
        ),
        "MEDIUM": sum(
            scan["medium_count"]
            for scan in history
        ),
        "LOW": sum(
            scan["low_count"]
            for scan in history
        ),
        "INFO": sum(
            scan["info_count"]
            for scan in history
        )
    }

    risk_history = []

    for scan in reversed(history):

        risk_history.append({
            "id": scan["id"],
            "target": scan["target"],
            "date": scan["scan_date"],
            "risk": scan["risk_score"],
            "level": scan["security_level"]
        })

    return jsonify({
        "success": True,
        "analytics": {
            "total_scans": total_scans,
            "unique_targets": unique_targets,
            "high_risk_scans": high_risk_scans,
            "average_risk": average_risk,
            "risk_history": risk_history,
            "severity_distribution": severity_distribution
        }
    })


# ============================================================
# REPORT
# ============================================================

@app.route("/api/report", methods=["POST"])
def create_report():

    data = request.get_json() or {}

    target = data.get(
        "target",
        "Unknown"
    )

    mode = data.get(
        "mode",
        "local"
    ).strip().lower()

    authorization_error = authorize_target(
        target,
        mode
    )

    if authorization_error:
        return authorization_error

    report = generate_report(
        target=target,
        assessment=data.get(
            "assessment",
            {}
        ),
        findings=data.get(
            "findings",
            []
        ),
        dns_result=data.get(
            "dns",
            {}
        ),
        traffic_result=data.get(
            "traffic",
            {}
        ),
        traceroute_result=data.get(
            "traceroute",
            {}
        )
    )

    return jsonify(report)


# ============================================================
# SERVE REPORTS
# ============================================================

@app.route("/reports/<path:filename>")
def serve_report(filename):

    return send_from_directory(
        os.path.join(
            PROJECT_ROOT,
            "reports"
        ),
        filename
    )


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
