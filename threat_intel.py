"""
threat_intel.py — MITRE ATT&CK Classification, HASSH Fingerprint Correlation, and Canary Honeytoken Detection
"""
import re

# Known HASSH signatures for rapid attacker tool identification
KNOWN_HASSH = {
    "0babd4b68a5f3757987be75fe35ad60a": "OpenSSH 9.x Client (Standard Linux / Cloud Node)",
    "b8e49c71708a20de29cf7f52f829ec96": "OpenSSH 8.x Client",
    "29fb59f0f9c4240751b3f9edb6b801a2": "PuTTY v0.7x (Windows Administrator / Threat Actor)",
    "00e26d24f0c8a6f3b0d49f6a73c1d48b": "Paramiko Python SSH Library (Automated Bot)",
    "73254922649a37e8c1cf27526715f187": "AsyncSSH / Twisted Python (Automated Scanner)",
    "d6e2469440656a848c48a73507cf7c48": "Golang crypto/ssh (Masscan / Automated Go Botnet)",
    "ff521b4a8e974e4c27a922d99d3d3ef0": "Dropbear SSH Client (Embedded / IoT / Router Bot)",
    "a442e3a1f87a8b417e30d41e77f0a8d6": "libssh / libssh2 (C/C++ Exploit Framework)",
    "6062f6b3e9a7e6b52861c8a6b22591b6": "ZGrab / ZMap Mass Scanner",
}

# Regex patterns for MITRE ATT&CK and Canary Honeytokens
CANARY_PATTERNS = [
    (re.compile(r"(\.aws|aws_access_key_id|AKIA4DEMOBAITKEY)", re.I), "AWS Cloud Credentials Honeytoken", "CRITICAL"),
    (re.compile(r"(\.env|SuperSecretP@ssw0rd|CANARY_TRIP|STRIPE_SECRET_KEY)", re.I), "Production .env Secrets Honeytoken", "CRITICAL"),
    (re.compile(r"(id_rsa|\.ssh/id_|BEGIN RSA PRIVATE)", re.I), "SSH Private Key Honeytoken", "CRITICAL"),
    (re.compile(r"(/etc/shadow|shadow\.bak)", re.I), "System Shadow Hashes Access", "HIGH"),
    (re.compile(r"(\.bash_history|\.sh_history)", re.I), "Shell History Snooping", "HIGH"),
]

MITRE_PATTERNS = [
    # Credential Access
    (re.compile(r"\b(cat|grep|tail|head)\b.*(\/etc\/passwd|\/etc\/shadow|\/etc\/master\.passwd)", re.I),
     "T1003", "OS Credential Dumping", "Credential Access", "HIGH"),
    
    # Ingress Tool Transfer (C2 / Malware drop)
    (re.compile(r"\b(curl|wget|tftp|ftpget|fetch|lwp-download)\b", re.I),
     "T1105", "Ingress Tool Transfer", "Command and Control", "HIGH"),
    
    # Defense Evasion
    (re.compile(r"\b(history\s+-c|rm\s+-[rf]*\s+.*log|unset\s+HISTFILE|killall\s+-9\s+syslogd)", re.I),
     "T1070", "Indicator Removal on Host", "Defense Evasion", "HIGH"),
    (re.compile(r"\b(iptables\s+-F|ufw\s+disable|systemctl\s+stop\s+firewalld)", re.I),
     "T1562", "Impair Defenses", "Defense Evasion", "CRITICAL"),
    
    # Discovery
    (re.compile(r"\b(uname\s+-a|cat\s+\/etc\/*release|cat\s+\/proc\/version|hostnamectl)\b", re.I),
     "T1082", "System Information Discovery", "Discovery", "LOW"),
    (re.compile(r"\b(ip\s+addr|ifconfig|route\s+-n|netstat|ss\s+-tulpn|arp\s+-a)\b", re.I),
     "T1016", "System Network Configuration", "Discovery", "LOW"),
    (re.compile(r"\b(ps\s+aux|ps\s+-ef|top|pstree)\b", re.I),
     "T1057", "Process Discovery", "Discovery", "LOW"),
    (re.compile(r"\b(whoami|id|w|who|last)\b", re.I),
     "T1033", "System Owner/User Discovery", "Discovery", "LOW"),
    
    # Persistence
    (re.compile(r"\b(crontab\s+-e|crontab\s+-l|\/etc\/cron\.)", re.I),
     "T1053", "Scheduled Task / Cron", "Persistence", "HIGH"),
    (re.compile(r"\b(useradd|adduser|usermod\s+-aG\s+sudo)", re.I),
     "T1136", "Create Account", "Persistence", "HIGH"),
    
    # Execution
    (re.compile(r"\b(chmod\s+\+x|chmod\s+777|chmod\s+755)\b", re.I),
     "T1222", "File Permissions Modification", "Execution", "MEDIUM"),
    (re.compile(r"\b(nohup|bash\s+-c|sh\s+-c|python\d*\s+-c|perl\s+-e)\b", re.I),
     "T1059.004", "Unix Shell Execution", "Execution", "MEDIUM"),
]

def classify_command(cmd: str) -> dict:
    """Analyze an attacker command and return MITRE ATT&CK tags and honeytoken alerts."""
    if not cmd or not isinstance(cmd, str):
        return {
            "mitre_id": "T1059",
            "mitre_name": "Command Execution",
            "tactic": "Execution",
            "severity": "LOW",
            "is_canary": False,
            "canary_name": None,
        }

    # 1. Check for Honeytokens
    is_canary = False
    canary_name = None
    for pattern, name, sev in CANARY_PATTERNS:
        if pattern.search(cmd):
            is_canary = True
            canary_name = name
            return {
                "mitre_id": "T1552",
                "mitre_name": "Unsecured Credentials (Honeytoken)",
                "tactic": "Credential Access",
                "severity": sev,
                "is_canary": True,
                "canary_name": canary_name,
                "warning": f"ALERT: Attacker tripped honeytoken: {canary_name}!"
            }

    # 2. Check MITRE ATT&CK patterns
    for pattern, m_id, name, tactic, sev in MITRE_PATTERNS:
        if pattern.search(cmd):
            return {
                "mitre_id": m_id,
                "mitre_name": name,
                "tactic": tactic,
                "severity": sev,
                "is_canary": False,
                "canary_name": None
            }

    # Default fallback
    return {
        "mitre_id": "T1059.004",
        "mitre_name": "Unix Shell",
        "tactic": "Execution",
        "severity": "LOW",
        "is_canary": False,
        "canary_name": None
    }

def get_hassh_identity(hassh: str) -> str:
    """Return recognized tool identity for a HASSH fingerprint."""
    if not hassh:
        return "Unknown Client"
    return KNOWN_HASSH.get(hassh, "Custom SSH Bot / Scanner")
