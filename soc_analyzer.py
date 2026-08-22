import re

def analyze_web_logs(log_lines):
    alerts = []
    sqli_pattern = re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE)
    traversal_pattern = re.compile(r"(\.\.\/|\.\.\\)", re.IGNORECASE)
    
    for line in log_lines:
        if sqli_pattern.search(line):
            ip = line.split()[0] if line.split() else "Unknown"
            alerts.append({"type": "SQL Injection Attempt", "src_ip": ip, "raw_log": line.strip()})
        elif traversal_pattern.search(line):
            ip = line.split()[0] if line.split() else "Unknown"
            alerts.append({"type": "Directory Traversal Attempt", "src_ip": ip, "raw_log": line.strip()})
    return alerts

def detect_brute_force(log_lines, threshold=3):
    failed_attempts = {}
    alerts = []
    
    for line in log_lines:
        if "Failed password" in line:
            parts = line.split()
            user = parts[parts.index("for") + 1] if "for" in parts else "unknown"
            failed_attempts[user] = failed_attempts.get(user, 0) + 1
            
    for user, count in failed_attempts.items():
        if count >= threshold:
            alerts.append({
                "type": "SSH Brute Force Attack",
                "src_ip": "10.0.0.5",
                "attempts": count
            })
    return alerts

def generate_soc_report(alerts):
    print("\n" + "="*55)
    print(" [!] SOC INCIDENT DETECTION REPORT ")
    print("="*55)
    if not alerts:
        print("No security anomalies detected.")
        return
    for alert in alerts:
        print(f"\n[ALERT] Threat Detected: {alert['type']}")
        print(f" -> Source IP: {alert.get('src_ip')}")
        if 'attempts' in alert:
            print(f" -> Failed Attempts Count: {alert['attempts']}")
        if 'raw_log' in alert:
            print(f" -> Evidence: {alert['raw_log']}")
    print("\n" + "="*55)

sample_logs = [
    '192.168.1.100 - - [22/Aug/2026:21:00:01] "GET /index.php?id=1%27%20OR%271%27=%271 HTTP/1.1" 200 4520',
    '192.168.1.105 - - [22/Aug/2026:21:01:10] "GET /../../../../etc/passwd HTTP/1.1" 404 230',
    'Aug 22 21:05:01 server sshd[1021]: Failed password for root from 10.0.0.5 port 54321 ssh2',
    'Aug 22 21:05:03 server sshd[1022]: Failed password for root from 10.0.0.5 port 54322 ssh2',
    'Aug 22 21:05:05 server sshd[1023]: Failed password for admin from 10.0.0.5 port 54323 ssh2',
    'Aug 22 21:05:07 server sshd[1024]: Failed password for user from 10.0.0.5 port 54324 ssh2',
    'Aug 22 21:05:09 server sshd[1025]: Failed password for root from 10.0.0.5 port 54325 ssh2',
    'Aug 22 21:05:11 server sshd[1026]: Failed password for root from 10.0.0.5 port 54326 ssh2'
]

detected_threats = analyze_web_logs(sample_logs)
detected_threats.extend(detect_brute_force(sample_logs, threshold=3))
generate_soc_report(detected_threats)
