import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    def __init__(self, time_window_seconds: int = 300):
        self.time_window_seconds = time_window_seconds

    def analyze_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parses login logs, aggregates by IP address, detects brute force patterns,
        and generates threat details.
        """
        ip_stats = {}
        for log in logs:
            ip = log.get("ip_address")
            if not ip:
                continue
            
            status = log.get("status")
            timestamp_str = log.get("timestamp", "")
            
            # Simple ISO time parsing
            try:
                # Strip Z or offset for datetime parsing
                ts_clean = timestamp_str.replace("Z", "")
                ts = datetime.fromisoformat(ts_clean)
            except Exception:
                ts = datetime.utcnow()

            if ip not in ip_stats:
                ip_stats[ip] = {
                    "failed_count": 0,
                    "success_count": 0,
                    "first_seen": ts,
                    "last_seen": ts,
                    "timestamps": []
                }
            
            stats = ip_stats[ip]
            stats["timestamps"].append(ts)
            if status == "failed":
                stats["failed_count"] += 1
            elif status == "success":
                stats["success_count"] += 1
            
            if ts < stats["first_seen"]:
                stats["first_seen"] = ts
            if ts > stats["last_seen"]:
                stats["last_seen"] = ts

        detected_threats = []
        for ip, stats in ip_stats.items():
            failed = stats["failed_count"]
            success = stats["success_count"]
            
            # Skip if no failures
            if failed == 0:
                continue

            # Calculate risk and severity based on failed counts
            risk_score = 0
            severity = "Low"
            recommended_action = "Monitor Activity"
            explanation = ""
            confidence = 100

            if failed >= 8:
                risk_score = min(90 + failed, 100)
                severity = "Critical"
                recommended_action = "Block IP"
                explanation = f"Critical alert: {failed} failed login attempts detected from a single IP ({ip}) in a short period. This matches a brute-force credential stuffing attack signature."
            elif failed >= 5:
                risk_score = 70 + (failed - 5) * 5
                severity = "High"
                recommended_action = "Block IP"
                explanation = f"High alert: {failed} failed login attempts detected from {ip}. High probability of malicious access scanning."
            elif failed >= 3:
                risk_score = 40 + (failed - 3) * 10
                severity = "Medium"
                recommended_action = "Monitor Activity"
                explanation = f"Medium alert: {failed} failed login attempts detected from {ip}. Rate exceeds normal parameters."
            else:
                risk_score = 10 + failed * 10
                severity = "Low"
                recommended_action = "Monitor Activity"
                explanation = f"Low alert: {failed} failed login attempts detected from {ip}. Likely user credential typo."

            # False Positive / Confidence tuning:
            # If there was a successful login from the same IP AFTER the failures,
            # it might be a user who forgot their password but finally remembered it.
            # Reduce confidence score drastically.
            if success > 0 and stats["last_seen"] == stats["timestamps"][-1] and success == 1:
                # Reduce confidence score to trigger false positive handling
                confidence = 55
                explanation += " Note: A successful login was observed immediately following failures, suggesting a forgotten password. Escalate as potential false positive."
                # Adjust recommendation to require human review
                recommended_action = "Require Human Approval"
            elif success > 2:
                # High SUCCESS count with failures could indicate distributed activity or a shared proxy
                confidence = 60
                explanation += " Note: Multiple success events observed from this IP. High likelihood of false positive/shared network."
                recommended_action = "Require Human Approval"

            threat_info = {
                "ip_address": ip,
                "threat_type": "Brute Force Attack" if failed >= 3 else "Suspicious Authentication Failures",
                "risk_score": risk_score,
                "severity": severity,
                "confidence": confidence,
                "recommended_action": recommended_action,
                "explanation": explanation,
                "stats": {
                    "failed_attempts": failed,
                    "successful_attempts": success
                }
            }
            detected_threats.append(threat_info)

        return detected_threats
