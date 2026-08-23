import logging
import requests
from typing import Dict, Any
from core.llm_client import call_llm, MODEL_DAST

logger = logging.getLogger("DASTAgent")

class DASTAgent:
    """Dynamic Application Security Testing Agent - powered by GLM-4."""

    def __init__(self, target_url: str):
        self.target_url = target_url

    def _fetch_headers(self) -> Dict[str, str]:
        """Fetch real HTTP security headers from the target."""
        try:
            resp = requests.get(self.target_url, timeout=10, allow_redirects=True)
            return {
                "HTTP Status": str(resp.status_code),
                "Content-Security-Policy": resp.headers.get("Content-Security-Policy", "❌ Missing"),
                "X-Frame-Options": resp.headers.get("X-Frame-Options", "❌ Missing"),
                "Strict-Transport-Security": resp.headers.get("Strict-Transport-Security", "❌ Missing"),
                "X-Content-Type-Options": resp.headers.get("X-Content-Type-Options", "❌ Missing"),
                "Referrer-Policy": resp.headers.get("Referrer-Policy", "❌ Missing"),
                "Permissions-Policy": resp.headers.get("Permissions-Policy", "❌ Missing"),
                "Server": resp.headers.get("Server", "Hidden"),
            }
        except Exception as e:
            return {"error": f"Cannot reach target: {str(e)}"}

    def run_dynamic_audit(self) -> Dict[str, Any]:
        logger.info(f"Starting DAST audit for: {self.target_url}")
        real_headers = self._fetch_headers()

        headers_text = "\n".join([f"  {k}: {v}" for k, v in real_headers.items()])
        prompt = f"""You are a penetration testing expert analyzing HTTP security headers.

Target: {self.target_url}
Headers found:
{headers_text}

Provide:
1. Risk assessment for each missing header
2. Specific attack scenarios enabled by these gaps (e.g., clickjacking via missing X-Frame-Options)
3. Overall security posture score (0-10)
4. Prioritized remediation steps (most critical first)

Be specific and technical."""

        analysis = call_llm(prompt, model=MODEL_DAST, max_tokens=600)
        return {
            "target_url": self.target_url,
            "status": "✅ DAST Audit Completed",
            "real_headers_scanned": real_headers,
            "ai_analysis": analysis,
            "findings": [
                {"type": k, "value": v, "severity": "High" if "❌" in str(v) else "OK"}
                for k, v in real_headers.items()
                if k not in ["HTTP Status", "Server", "error"]
            ]
        }
