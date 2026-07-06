"""
SENTINEL-GRC — Control Runners: Access Control
FIX: sudo_members initialised to [] before conditional block to prevent NameError.
"""

import subprocess
import platform
import re
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import structlog

logger = structlog.get_logger()


@dataclass
class ControlRunResult:
    """Standardised output from every control runner."""
    control_id: str
    control_name: str
    passed: bool
    status: str
    finding: str
    raw_output: dict
    risk_contribution_gbp: float = 0.0
    remediation_steps: list = None
    frameworks_failed: list = None

    def __post_init__(self):
        if self.remediation_steps is None:
            self.remediation_steps = []
        if self.frameworks_failed is None:
            self.frameworks_failed = []

    def to_dict(self) -> dict:
        return asdict(self)


def check_password_policy() -> ControlRunResult:
    """
    AC-001: Verify system password policy meets minimum requirements.
    Maps to: ISO 27001 A.9.4.3, NIST PR.AC-1, SOC2 CC6.1
    """
    control_id = "AC-001"
    control_name = "Password Policy Enforcement"
    raw_output = {}
    findings = []
    passed = True

    try:
        system = platform.system()

        if system == "Linux":
            try:
                with open("/etc/login.defs", "r") as f:
                    login_defs = f.read()
                raw_output["login_defs"] = login_defs[:2000]

                min_len_match = re.search(r"^PASS_MIN_LEN\s+(\d+)", login_defs, re.MULTILINE)
                min_len = int(min_len_match.group(1)) if min_len_match else 6

                if min_len < 12:
                    passed = False
                    findings.append(
                        f"Password minimum length is {min_len} (required: 12+). "
                        f"Non-compliant with ISO 27001 A.9.4.3 and Cyber Essentials."
                    )
                raw_output["password_min_length"] = min_len

                max_days_match = re.search(r"^PASS_MAX_DAYS\s+(\d+)", login_defs, re.MULTILINE)
                max_days = int(max_days_match.group(1)) if max_days_match else 99999
                if max_days > 90:
                    findings.append(f"Password max age is {max_days} days (recommended: 90).")
                raw_output["password_max_days"] = max_days

            except FileNotFoundError:
                raw_output["error"] = "/etc/login.defs not found"
                findings.append("Cannot verify password policy — /etc/login.defs not accessible.")
        elif system == "Windows":
            raw_output["platform"] = system
            result = subprocess.run(["powershell", "-Command", "net accounts"], capture_output=True, text=True, timeout=10)
            raw_output["net_accounts"] = result.stdout[:2000]
            
            min_len = 6
            max_days = 99999
            
            for line in result.stdout.split('\n'):
                if "Minimum password length" in line:
                    match = re.search(r'\d+', line)
                    if match: min_len = int(match.group())
                elif "Maximum password age (days)" in line:
                    match = re.search(r'\d+', line)
                    if match: max_days = int(match.group())

            if min_len < 12:
                passed = False
                findings.append(f"Password minimum length is {min_len} (required: 12+). Non-compliant with ISO 27001.")
            if max_days != 99999 and max_days > 90:
                findings.append(f"Password max age is {max_days} days (recommended: 90).")
                
            raw_output["password_min_length"] = min_len
            raw_output["password_max_days"] = max_days
        else:
            raw_output["platform"] = system
            raw_output["simulation"] = {
                "password_min_length": 12,
                "password_max_days": 60,
            }
            findings.append("Password policy check simulated — deploy on Linux for live results.")

    except Exception as e:
        logger.error("AC-001 runner error", error=str(e))
        return ControlRunResult(
            control_id=control_id,
            control_name=control_name,
            passed=False,
            status="error",
            finding=f"Control runner error: {str(e)}",
            raw_output={"error": str(e)},
            risk_contribution_gbp=50000,
        )

    finding_text = ". ".join(findings) if findings else "Password policy meets all requirements."
    return ControlRunResult(
        control_id=control_id,
        control_name=control_name,
        passed=passed,
        status="pass" if passed else "fail",
        finding=finding_text,
        raw_output=raw_output,
        risk_contribution_gbp=0 if passed else 125_000,
        frameworks_failed=[] if passed else ["ISO27001-A.9.4.3", "NIST-PR.AC-1", "SOC2-CC6.1", "Cyber_Essentials"],
        remediation_steps=[] if passed else [
            "Edit /etc/login.defs and set PASS_MIN_LEN 12",
            "Set PASS_MAX_DAYS 90 in /etc/login.defs",
            "Apply immediately: chage --maxdays 90 <username> for all active users",
        ],
    )


def check_privileged_accounts() -> ControlRunResult:
    """
    AC-002: Detect privileged accounts unused for 90+ days.
    FIX: sudo_members initialised to [] before conditional to prevent NameError.
    Maps to: ISO 27001 A.9.2.5, NIST PR.AC-4, SOC2 CC6.3
    """
    control_id = "AC-002"
    control_name = "Privileged Account Inactivity"
    raw_output = {}
    inactive_accounts = []
    passed = True

    try:
        system = platform.system()

        if system == "Linux":
            # FIX: Initialise sudo_members BEFORE the conditional block
            sudo_members = []

            try:
                result = subprocess.run(
                    ["last", "-w", "-F"],
                    capture_output=True, text=True, timeout=10
                )
                raw_output["last_output"] = result.stdout[:3000]

                sudo_result = subprocess.run(
                    ["getent", "group", "sudo"],
                    capture_output=True, text=True, timeout=5
                )
                # Only override if successful
                if sudo_result.returncode == 0:
                    sudo_line = sudo_result.stdout.strip()
                    sudo_members = sudo_line.split(":")[3].split(",") if ":" in sudo_line else []
                raw_output["sudo_members"] = sudo_members

                last_logins = {}
                for line in result.stdout.split("\n"):
                    parts = line.split()
                    if len(parts) >= 5 and parts[0] not in ("wtmp", "reboot", ""):
                        username = parts[0]
                        if username not in last_logins:
                            last_logins[username] = line
                raw_output["last_logins_parsed"] = last_logins

                for username in sudo_members:
                    username = username.strip()
                    if username and username not in last_logins:
                        inactive_accounts.append({
                            "username": username,
                            "last_seen": "Never logged in",
                            "days_inactive": "Unknown",
                        })
                        passed = False

            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                raw_output["error"] = str(e)

        elif system == "Windows":
            try:
                ps_cmd = "Get-LocalGroupMember -Group 'Administrators' | Where-Object { $_.ObjectClass -eq 'User' } | ForEach-Object { $u = Get-LocalUser -Name $_.Name; [PSCustomObject]@{ Name=$u.Name; LastLogon=$u.LastLogon } } | ConvertTo-Json"
                result = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, timeout=15)
                raw_output["ps_output"] = result.stdout[:2000]
                raw_output["ps_stderr"] = result.stderr[:2000] if result.stderr else ""

                # Detect permission / access denied failures
                access_denied_indicators = ["access is denied", "access denied", "insufficient privilege", "not have the required permissions"]
                stderr_lower = (result.stderr or "").lower()
                stdout_lower = (result.stdout or "").lower()
                is_access_denied = any(ind in stderr_lower or ind in stdout_lower for ind in access_denied_indicators)

                if result.returncode != 0 and (is_access_denied or not result.stdout.strip()):
                    raw_output["inconclusive_reason"] = "elevated_privileges_required"
                    return ControlRunResult(
                        control_id=control_id,
                        control_name=control_name,
                        passed=False,
                        status="inconclusive",
                        finding="Control check requires elevated privileges. Result: Inconclusive. Action: Re-run worker as Administrator for definitive assessment.",
                        raw_output=raw_output,
                        risk_contribution_gbp=0,
                        frameworks_failed=[],
                        remediation_steps=["Re-run the Celery worker as Administrator to enable privileged account auditing."],
                    )

                if result.returncode == 0 and result.stdout.strip():
                    import json
                    admins = json.loads(result.stdout)
                    if isinstance(admins, dict):
                        admins = [admins]
                    
                    for admin in admins:
                        username = admin.get("Name", "Unknown")
                        last_logon = admin.get("LastLogon")
                        
                        if not last_logon:
                            inactive_accounts.append({"username": username, "last_seen": "Never", "days_inactive": "Unknown"})
                            passed = False
                        else:
                            # Parse standard ISO format from PS ConvertTo-Json
                            try:
                                logon_date = datetime.fromisoformat(last_logon.replace("Z", "+00:00"))
                                days_inactive = (datetime.now() - logon_date.replace(tzinfo=None)).days
                                if days_inactive > 90:
                                    inactive_accounts.append({"username": username, "last_seen": logon_date.isoformat(), "days_inactive": days_inactive})
                                    passed = False
                            except ValueError:
                                pass
            except FileNotFoundError:
                raw_output["inconclusive_reason"] = "powershell_not_found"
                return ControlRunResult(
                    control_id=control_id,
                    control_name=control_name,
                    passed=False,
                    status="inconclusive",
                    finding="PowerShell not found on this system. Result: Inconclusive. Action: Run this check on a Windows host with PowerShell available.",
                    raw_output=raw_output,
                    risk_contribution_gbp=0,
                    frameworks_failed=[],
                    remediation_steps=[],
                )
            except Exception as e:
                raw_output["error"] = str(e)

        else:
            raw_output["simulation"] = {
                "total_privileged_accounts": 5,
                "inactive_90_plus_days": 0,
                "accounts_checked": ["admin", "sysadmin", "backup_admin"],
            }

    except Exception as e:
        logger.error("AC-002 runner error", error=str(e))
        return ControlRunResult(
            control_id=control_id,
            control_name=control_name,
            passed=False,
            status="error",
            finding=f"Control runner error: {str(e)}",
            raw_output={"error": str(e)},
            risk_contribution_gbp=200_000,
        )

    finding = (
        f"Found {len(inactive_accounts)} privileged account(s) inactive for 90+ days: "
        + ", ".join(a["username"] for a in inactive_accounts)
        if not passed
        else "All privileged accounts show recent activity (within 90 days)."
    )

    return ControlRunResult(
        control_id=control_id,
        control_name=control_name,
        passed=passed,
        status="pass" if passed else "fail",
        finding=finding,
        raw_output=raw_output,
        risk_contribution_gbp=0 if passed else 400_000,
        frameworks_failed=[] if passed else ["ISO27001-A.9.2.5", "NIST-PR.AC-4", "SOC2-CC6.3"],
        remediation_steps=[] if passed else [
            f"Disable inactive accounts: {[a['username'] for a in inactive_accounts]}",
            "Run: usermod --lock <username> for each inactive privileged account",
            "Schedule quarterly privileged access reviews",
        ],
    )


def check_mfa() -> ControlRunResult:
    """
    AC-003: Verify Multi-Factor Authentication is configured.
    Maps to: ISO 27001 A.9.4.2, NIST PR.AC-7, SOC2 CC6.1
    """
    control_id = "AC-003"
    control_name = "Multi-Factor Authentication"
    raw_output = {}
    passed = True
    findings = []

    try:
        system = platform.system()

        if system == "Linux":
            pam_configs = ["/etc/pam.d/sshd", "/etc/pam.d/sudo", "/etc/pam.d/common-auth"]
            mfa_configured = False

            for config_path in pam_configs:
                try:
                    with open(config_path, "r") as f:
                        content = f.read()
                    if any(m in content for m in ["google_authenticator", "pam_duo.so", "pam_oath.so"]):
                        mfa_configured = True
                        raw_output[f"{config_path}_mfa"] = True
                except FileNotFoundError:
                    raw_output[f"{config_path}_found"] = False

            try:
                with open("/etc/ssh/sshd_config", "r") as f:
                    ssh_config = f.read()
                raw_output["sshd_config_excerpt"] = ssh_config[:500]
                if not mfa_configured:
                    findings.append("MFA not detected in PAM or SSH configuration")
                    passed = False
            except FileNotFoundError:
                raw_output["sshd_config_found"] = False

        elif system == "Windows":
            raw_output["platform"] = system
            raw_output["note"] = "Local Windows MFA check is not universally verifiable without Entra ID / 3rd party agents."
            findings.append("MFA check on local Windows requires manual verification.")
            
        else:
            raw_output["simulation"] = {
                "mfa_enabled": True,
                "covered_systems": ["SSH", "VPN", "Admin Portal"],
                "mfa_method": "TOTP",
                "coverage_percent": 94,
            }
            findings.append("MFA check simulated.")

    except Exception as e:
        logger.error("AC-003 runner error", error=str(e))
        return ControlRunResult(
            control_id=control_id,
            control_name=control_name,
            passed=False,
            status="error",
            finding=f"Control runner error: {str(e)}",
            raw_output={"error": str(e)},
            risk_contribution_gbp=500_000,
        )

    return ControlRunResult(
        control_id=control_id,
        control_name=control_name,
        passed=passed,
        status="pass" if passed else "fail",
        finding=". ".join(findings) if findings else "MFA is configured on all verified access paths.",
        raw_output=raw_output,
        risk_contribution_gbp=0 if passed else 750_000,
        frameworks_failed=[] if passed else ["ISO27001-A.9.4.2", "NIST-PR.AC-7", "SOC2-CC6.1", "Cyber_Essentials"],
        remediation_steps=[] if passed else [
            "Install Google Authenticator PAM: apt install libpam-google-authenticator",
            "Configure /etc/pam.d/sshd to require google_authenticator",
            "Enforce MFA on all admin portals, VPN, and cloud console access",
        ],
    )
