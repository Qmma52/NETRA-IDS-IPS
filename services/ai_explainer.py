# services/ai_explainer.py
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

@dataclass
class ExplainResult:
    ok: bool
    message: str
    model: Optional[str] = None
    used_ai: bool = False


def _rule_to_attack_type(rule_name: str) -> str:
    name = (rule_name or "").lower()
    if "brute" in name:
        return "Brute Force Login / Credential Attack"
    if "port" in name:
        return "Port Scanning / Reconnaissance"
    if "traffic" in name or "ddos" in name:
        return "Traffic Spike / Possible DDoS"
    if "cpu" in name:
        return "CPU Spike / Possible Malware or Crypto-mining"
    if "file" in name or "integrity" in name:
        return "Suspicious File Change / Possible Tampering"
    return "Suspicious Activity"


def explain_alert(alert: Dict[str, Any]) -> ExplainResult:
    """
    alert example keys:
      time, src_ip, rule, type, severity, details, ml_anomaly, anomaly_score
    """
    rule = str(alert.get("rule", ""))
    ip = str(alert.get("src_ip", ""))
    sev = str(alert.get("severity", ""))
    det = str(alert.get("details", ""))
    ml = bool(alert.get("ml_anomaly", False))
    score = alert.get("anomaly_score", None)

    attack_type = _rule_to_attack_type(rule)

    # ---- If OpenAI key exists, try AI ----
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("IDS_OPENAI_API_KEY")
    model = os.getenv("IDS_AI_MODEL", "gpt-4o-mini")

    if api_key:
        try:
            from openai import OpenAI  # openai>=1.x
            client = OpenAI(api_key=api_key)

            prompt = f"""
You are a cybersecurity SOC analyst.
Explain this IDS alert in simple, professional English (bullet points + short paragraphs).
Include:
- What likely happened (attack type)
- Evidence from fields
- Risk/impact
- Why blocking might be recommended (or not)
- What to check next (2-4 steps)
Keep it student-friendly.

ALERT DATA:
Time: {alert.get('time')}
Source IP: {ip}
Rule Triggered: {rule}
Rule Type: {alert.get('type')}
Severity: {sev}
Details: {det}
ML Anomaly: {ml}
Anomaly Score: {score}
"""

            resp = client.responses.create(
                model=model,
                input=prompt,
            )
            text = resp.output_text.strip() if hasattr(resp, "output_text") else str(resp)

            if not text:
                raise RuntimeError("Empty AI response")

            return ExplainResult(ok=True, message=text, model=model, used_ai=True)

        except Exception as e:
            # fallback to template if AI fails
            fallback = _template_explain(alert, attack_type)
            fallback += f"\n\n(⚠️ AI failed, fallback used. Error: {e})"
            return ExplainResult(ok=True, message=fallback, model=model, used_ai=False)

    # ---- No key: template explanation ----
    return ExplainResult(ok=True, message=_template_explain(alert, attack_type), used_ai=False)


def _template_explain(alert: Dict[str, Any], attack_type: str) -> str:
    ip = str(alert.get("src_ip", ""))
    rule = str(alert.get("rule", ""))
    sev = str(alert.get("severity", ""))
    det = str(alert.get("details", ""))
    ml = bool(alert.get("ml_anomaly", False))
    score = alert.get("anomaly_score", "N/A")

    rec = "Recommended" if sev.lower() in ["high", "medium"] else "Optional"

    lines = []
    lines.append(f"### 🧠 Alert Explanation (Template)")
    lines.append(f"**Attack Type (likely):** {attack_type}")
    lines.append("")
    lines.append(f"**What happened:**")
    lines.append(f"- The IDS rule **{rule}** was triggered for source IP **{ip}**.")
    lines.append(f"- Severity is **{sev}**.")
    if det:
        lines.append(f"- Rule detail: {det}")

    lines.append("")
    lines.append(f"**Evidence from this event:**")
    lines.append(f"- ML anomaly flag: **{ml}** | anomaly score: **{score}**")

    lines.append("")
    lines.append("**Risk / Impact:**")
    if "Brute" in attack_type:
        lines.append("- Account compromise risk if password guessing continues.")
        lines.append("- Could lead to unauthorized access.")
    elif "Port" in attack_type:
        lines.append("- Recon phase: attacker mapping open services/ports.")
        lines.append("- Could lead to exploitation of vulnerable ports.")
    elif "DDoS" in attack_type or "Traffic" in attack_type:
        lines.append("- Service slowdown / downtime risk.")
        lines.append("- May exhaust bandwidth/resources.")
    elif "CPU" in attack_type:
        lines.append("- Possible malware/crypto-miner consuming CPU.")
        lines.append("- Performance degradation and suspicious process activity.")
    else:
        lines.append("- Suspicious activity that may indicate compromise or probing.")

    lines.append("")
    lines.append(f"**Block Recommendation:** {rec}")
    lines.append("- Blocking is typically recommended if the IP is unknown/untrusted, repeated, or causing disruption.")
    lines.append("- If IP belongs to your own LAN user/device, verify first before blocking.")

    lines.append("")
    lines.append("**What to check next (quick):**")
    lines.append("1) Check if this IP is internal or external (LAN vs internet).")
    lines.append("2) Look for repeated events from the same IP in Events table.")
    lines.append("3) If repeated High/Medium alerts → block (admin).")
    lines.append("4) Confirm firewall rule exists in Windows Firewall rules list.")

    return "\n".join(lines)
