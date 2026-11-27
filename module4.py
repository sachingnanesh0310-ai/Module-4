
import socket
import ipaddress
import subprocess
import shutil
import re
import os
from datetime import datetime
from pathlib import Path

# ==========================================
# ETHICAL HACKING & VULNERABILITY ASSESSMENT
# ==========================================

report = []

def log(message):
    print(message)
    report.append(str(message))

# ==========================================
# 1. ETHICAL HACKING LIFECYCLE
# ==========================================

def ethical_hacking_lifecycle():

    log("\n========== ETHICAL HACKING LIFECYCLE ==========")

    log("""
1. Planning:
   Define the authorized testing scope.

2. Asset Discovery:
   Identify systems and network assets.

3. Reconnaissance:
   Collect information about the target.

4. Enumeration:
   Identify network services and ports.

5. Vulnerability Assessment:
   Identify potential security weaknesses.

6. Risk Analysis:
   Prioritize vulnerabilities.

7. Remediation:
   Recommend security improvements.

8. Reporting:
   Document findings and conclusions.
""")

# ==========================================
# 2. ASSET DISCOVERY AND DNS
# ==========================================

def asset_discovery():

    log("\n========== ASSET DISCOVERY ==========")

    domain = input(
        "Enter a domain for DNS information: "
    ).strip()

    if not domain:
        log("Domain cannot be empty.")
        return

    try:
        addresses = socket.getaddrinfo(domain, None)

        unique_ips = sorted(set(
            item[4][0] for item in addresses
        ))

        log(f"Domain: {domain}")

        for ip in unique_ips:
            log(f"Discovered IP: {ip}")

        log("Asset discovery completed.")

    except socket.gaierror:
        log("Unable to resolve domain.")

# ==========================================
# 3. AUTHORIZED NETWORK ENUMERATION
# ==========================================

def network_enumeration():

    log("\n========== NETWORK ENUMERATION ==========")

    target = input(
        "Enter your private/local lab IP: "
    ).strip()

    try:
        ip = ipaddress.ip_address(target)

        if not (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local
        ):
            log("Only private/local lab IPs are permitted.")
            return

    except ValueError:
        log("Invalid IP address.")
        return

    confirm = input(
        "Do you own or have permission to test this IP? (yes/no): "
    ).strip().lower()

    if confirm != "yes":
        log("Testing cancelled.")
        return

    ports = {
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MYSQL",
        8080: "HTTP-ALT"
    }

    log(f"Scanning authorized target: {target}")

    for port, service in ports.items():

        try:
            connection = socket.socket(
                socket.AF_INET if ip.version == 4
                else socket.AF_INET6,
                socket.SOCK_STREAM
            )

            connection.settimeout(0.5)

            result = connection.connect_ex(
                (target, port)
            )

            if result == 0:
                log(f"Port {port} OPEN - {service}")
            else:
                log(f"Port {port} CLOSED/FILTERED - {service}")

            connection.close()

        except OSError as error:
            log(f"Port {port}: Error - {error}")

    log("Enumeration completed.")

# ==========================================
# 4. NMAP SECURITY SCANNING
# ==========================================

def nmap_scan():

    log("\n========== NMAP SCANNING ==========")

    if shutil.which("nmap") is None:
        log("Nmap is not installed.")
        log("Download it from https://nmap.org/download.html")
        return

    target = input(
        "Enter authorized private/local IP: "
    ).strip()

    try:
        ip = ipaddress.ip_address(target)

        if not (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local
        ):
            log("Public IP scanning is not allowed.")
            return

    except ValueError:
        log("Invalid IP address.")
        return

    confirmation = input(
        "Confirm authorization (yes/no): "
    ).strip().lower()

    if confirmation != "yes":
        log("Scan cancelled.")
        return

    log("Starting limited Nmap service scan...")

    try:

        result = subprocess.run(
            [
                "nmap",
                "-sT",
                "-sV",
                "--top-ports",
                "20",
                "-T2",
                target
            ],
            capture_output=True,
            text=True,
            timeout=120
        )

        log(result.stdout)

        if result.stderr:
            log(result.stderr)

    except subprocess.TimeoutExpired:
        log("Nmap scan timed out.")

    except Exception as error:
        log(f"Scanning error: {error}")

# ==========================================
# 5. PASSWORD SECURITY TESTING
# ==========================================

def password_security():

    log("\n========== PASSWORD SECURITY ==========")

    password = input(
        "Enter a sample password to evaluate: "
    )

    if len(password) < 8:
        log("Weak: Password is too short.")

    elif len(password) < 12:
        log("Moderate: Use at least 12 characters.")

    else:
        log("Good length: Password has 12+ characters.")

    checks = {
        "Uppercase letters": bool(re.search(r"[A-Z]", password)),
        "Lowercase letters": bool(re.search(r"[a-z]", password)),
        "Numbers": bool(re.search(r"[0-9]", password)),
        "Special characters": bool(re.search(r"[^A-Za-z0-9]", password))
    }

    for name, passed in checks.items():
        log(f"{name}: {'PASS' if passed else 'MISSING'}")

    score = sum(checks.values())

    log(f"Complexity checks passed: {score}/4")

    if len(password) >= 12 and score == 4:
        log("Result: Strong password characteristics.")
    else:
        log("Result: Password needs improvement.")

    log("Note: This is a basic educational check, not a full password audit.")

# ==========================================
# 6. CVE AND CVSS RISK CLASSIFICATION
# ==========================================

def vulnerability_assessment():

    log("\n========== VULNERABILITY ASSESSMENT ==========")

    cve = input(
        "Enter CVE ID (example: CVE-2024-12345): "
    ).strip().upper()

    if not re.fullmatch(
        r"CVE-\d{4}-\d{4,}",
        cve
    ):
        log("Invalid CVE ID format.")
        return

    log(f"CVE Identifier: {cve}")

    try:
        score = float(input(
            "Enter verified CVSS base score (0.0-10.0): "
        ))

        if not 0 <= score <= 10:
            log("CVSS score must be between 0 and 10.")
            return

    except ValueError:
        log("Invalid CVSS score.")
        return

    if score == 0:
        severity = "NONE"
    elif score < 4:
        severity = "LOW"
    elif score < 7:
        severity = "MEDIUM"
    elif score < 9:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    log(f"CVSS Score: {score}")
    log(f"Risk Classification: {severity}")

    log("""
CVSS SEVERITY REFERENCE:

0.0       - NONE
0.1-3.9   - LOW
4.0-6.9   - MEDIUM
7.0-8.9   - HIGH
9.0-10.0 - CRITICAL
""")

    log("Use the official CVE record to verify the vulnerability and score.")

# ==========================================
# 7. THREAT MODELING
# ==========================================

def threat_modeling():

    log("\n========== THREAT MODELING ==========")

    log("""
STRIDE THREAT MODEL:

1. Spoofing:
   Attacker pretends to be a legitimate user.
   Solution: Strong authentication.

2. Tampering:
   Unauthorized modification of data.
   Solution: Input validation and integrity checks.

3. Repudiation:
   Denial of performed actions.
   Solution: Security logging and auditing.

4. Information Disclosure:
   Exposure of confidential information.
   Solution: Encryption and access control.

5. Denial of Service:
   Making services unavailable.
   Solution: Rate limiting and monitoring.

6. Elevation of Privilege:
   Unauthorized access to higher privileges.
   Solution: Least privilege principle.
""")

# ==========================================
# 8. REMEDIATION RECOMMENDATIONS
# ==========================================

def remediation_plan():

    log("\n========== REMEDIATION PLAN ==========")

    log("""
SECURITY RECOMMENDATIONS:

1. Close unnecessary open ports.
2. Update outdated software.
3. Use strong passwords.
4. Enable multi-factor authentication.
5. Apply security patches.
6. Restrict unauthorized access.
7. Encrypt sensitive information.
8. Monitor suspicious network activity.
9. Follow least privilege principles.
10. Perform regular security assessments.
""")

# ==========================================
# 9. GENERATE PROFESSIONAL REPORTS
# ==========================================

def generate_reports():

    log("\n========== GENERATING REPORTS ==========")

    folder = Path("Reports")
    folder.mkdir(exist_ok=True)

    date = datetime.now().strftime("%d-%m-%Y %H:%M")

    # Main assessment report
    assessment = f"""
ETHICAL HACKING & VULNERABILITY ASSESSMENT REPORT

Date: {date}

PROJECT OBJECTIVES:

1. Understand ethical hacking lifecycle.
2. Perform asset discovery.
3. Understand reconnaissance and enumeration.
4. Evaluate password security.
5. Study CVE and CVSS.
6. Perform vulnerability assessment.
7. Prepare remediation recommendations.

ACTIVITIES:

{chr(10).join(report)}

CONCLUSION:

The Ethical Hacking and Vulnerability Assessment
Lab demonstrates authorized security testing,
risk classification and remediation planning.

All active tests must be restricted to systems
where permission has been granted.
"""

    risk = """
RISK CLASSIFICATION REPORT

CRITICAL:
CVSS 9.0 - 10.0
Immediate attention required.

HIGH:
CVSS 7.0 - 8.9
Prioritize remediation.

MEDIUM:
CVSS 4.0 - 6.9
Schedule remediation.

LOW:
CVSS 0.1 - 3.9
Address through routine maintenance.

NONE:
CVSS 0.0
No CVSS base severity assigned.
"""

    remediation = """
REMEDIATION PLAN

1. Identify affected assets.
2. Verify reported vulnerabilities.
3. Determine business impact.
4. Prioritize based on risk.
5. Apply security patches.
6. Close unnecessary ports.
7. Improve authentication.
8. Restrict access privileges.
9. Retest after remediation.
10. Document final results.

CONCLUSION:

Regular vulnerability assessment and remediation
help maintain a secure computing environment.
"""

    files = {
        "Vulnerability_Assessment_Report.txt": assessment,
        "Risk_Classification.txt": risk,
        "Remediation_Plan.txt": remediation
    }

    for filename, content in files.items():

        with open(
            folder / filename,
            "w",
            encoding="utf-8"
        ) as file:
            file.write(content)

        print("Generated:", folder / filename)

    print("\nAll reports generated successfully!")

# ==========================================
# MAIN MENU
# ==========================================

def main():

    print("\n============================================")
    print(" ETHICAL HACKING & VULNERABILITY ASSESSMENT")
    print("============================================")

    while True:

        print("""
1. Ethical Hacking Lifecycle
2. Asset Discovery and DNS
3. Network Enumeration
4. Nmap Security Scanning
5. Password Security Testing
6. CVE and CVSS Assessment
7. Threat Modeling (STRIDE)
8. Remediation Recommendations
9. Generate Assessment Reports
10. Exit
""")

        choice = input("Enter your choice: ")

        if choice == "1":
            ethical_hacking_lifecycle()

        elif choice == "2":
            asset_discovery()

        elif choice == "3":
            network_enumeration()

        elif choice == "4":
            nmap_scan()

        elif choice == "5":
            password_security()

        elif choice == "6":
            vulnerability_assessment()

        elif choice == "7":
            threat_modeling()

        elif choice == "8":
            remediation_plan()

        elif choice == "9":
            generate_reports()

        elif choice == "10":
            print("Exiting Ethical Hacking Lab...")
            break

        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()