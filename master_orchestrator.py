import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
import json
from typing import Dict, Any, Optional
from core.sast_agent import SASTAgent
from core.dast_agent import DASTAgent
from core.remediation_agent import RemediationAgent
from utils.session_manager import SessionManager
from utils.cloud_sync import CloudSyncManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("MasterOrchestrator")

def _map_mitre_stride(findings: list) -> list:
    """Enriches findings with MITRE ATT&CK techniques and STRIDE threat model categories."""
    enriched = []
    for f in findings:
        cwe = str(f.get("cwe", "")).lower()
        issue = str(f.get("snippet", f.get("type", ""))).lower()
        
        mitre = "T1190 (Exploit Public-Facing Application)"
        stride = "Tampering"
        
        if "sql" in cwe or "sql" in issue:
            mitre = "T1190 (SQL Injection Injection)"
            stride = "Tampering & Information Disclosure"
            severity = f.get("severity", "High")
        elif "eval" in cwe or "code" in cwe or "exec" in issue:
            mitre = "T1059 (Command and Scripting Interpreter)"
            stride = "Elevation of Privilege"
            severity = f.get("severity", "Critical")
        elif "header" in issue or "missing" in issue:
            mitre = "T1557 (Man-in-the-Middle / Protocol Weakness)"
            stride = "Information Disclosure"
            severity = f.get("severity", "Medium")
        else:
            severity = f.get("severity", "Medium")
            
        enriched.append({
            **f,
            "severity": severity,
            "mitre_attack": mitre,
            "stride_category": stride
        })
    return enriched

class AutonomousHexStrikeOrchestrator:
    """Master Autonomous Orchestrator (HexStrike AI Architecture).
    Integrates Recon -> DeepSeek Autonomous Decision -> Heavy OS Probes -> Unified Context -> GLM Patch Sandbox.
    """

    def __init__(self):
        self.session_manager = SessionManager()
        self.cloud_sync = CloudSyncManager()
        self.remediation_agent = RemediationAgent()

    def run_autonomous_pipeline(self, session_id: str, code_snippet: Optional[str] = None) -> Dict[str, Any]:
        session = self.session_manager.load_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found.")

        target_url = session.get("target_url", "")
        logger.info(f"🚀 Starting Autonomous HexStrike Pipeline for Session {session_id} - Target: {target_url}")

        # 1. Recon Phase
        dast_agent = DASTAgent(target_url)
        dast_results = dast_agent.run_dynamic_audit()

        # 2. SAST Analysis
        sast_agent = SASTAgent()
        sample_code = code_snippet or "query = 'SELECT * FROM users WHERE name = ' + user_input\neval(user_input)"
        raw_sast = sast_agent.analyze_source_code(sample_code)
        sast_results = _map_mitre_stride(raw_sast)

        # 3. Unified Context Aggregation
        unified_memory = {
            "session_id": session_id,
            "target_url": target_url,
            "dast_findings": dast_results.get("findings", []),
            "sast_findings": sast_results,
            "real_headers": dast_results.get("real_headers_scanned", {})
        }

        # 4. Remediation & PyTest Sandbox Verification
        patches = []
        for finding in sast_results:
            if finding.get("severity") in ["Critical", "High"]:
                patch = self.remediation_agent.generate_patch(finding)
                patches.append(patch)

        session["dast_results"] = [dast_results]
        session["sast_results"] = sast_results
        session["remediation_patches"] = patches
        session["unified_memory"] = unified_memory

        self.session_manager.save_session(session)
        logger.info(f"✅ Autonomous Pipeline Completed for {session_id[:8]}")
        return session

class MasterOrchestrator(AutonomousHexStrikeOrchestrator):
    """Legacy alias for MasterOrchestrator."""
    def run_full_audit_pipeline(self, session_id: str, code_snippet: Optional[str] = None) -> Dict[str, Any]:
        return self.run_autonomous_pipeline(session_id, code_snippet)

if __name__ == "__main__":
    orchestrator = MasterOrchestrator()
    new_sess = orchestrator.session_manager.create_session("Test Audit Project", "http://staging.local")
    results = orchestrator.run_full_audit_pipeline(new_sess["session_id"])
    print(json.dumps(results, indent=2))

