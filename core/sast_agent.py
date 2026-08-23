import logging
from typing import Dict, Any, List
from core.llm_client import call_llm, MODEL_SAST

logger = logging.getLogger("SASTAgent")

class SASTAgent:
    """Static Application Security Testing Agent - powered by DeepSeek-R1."""

    def analyze_source_code(self, code_snippet: str, file_path: str = "src/app.py") -> List[Dict[str, Any]]:
        logger.info(f"Analyzing {file_path} with DeepSeek-R1 via HF Router...")
        findings = []

        # --- Static rule-based detection (always runs, no API needed) ---
        lines = code_snippet.split("\n")
        for idx, line in enumerate(lines, start=1):
            if "SELECT" in line and "+" in line and ("query" in line.lower() or "sql" in line.lower()):
                findings.append({
                    "file": file_path, "line": idx,
                    "cwe": "CWE-89 (SQL Injection)", "severity": "High",
                    "snippet": line.strip(),
                    "recommendation": "Use parameterized queries or ORM bindings instead of string concatenation."
                })
            elif "eval(" in line or "exec(" in line:
                findings.append({
                    "file": file_path, "line": idx,
                    "cwe": "CWE-95 (Code Injection)", "severity": "Critical",
                    "snippet": line.strip(),
                    "recommendation": "Never use eval/exec on untrusted user input."
                })
            elif "password" in line.lower() and "=" in line and '"' in line and not line.strip().startswith("#"):
                findings.append({
                    "file": file_path, "line": idx,
                    "cwe": "CWE-798 (Hardcoded Credentials)", "severity": "High",
                    "snippet": line.strip(),
                    "recommendation": "Use environment variables or a secrets manager for credentials."
                })
            elif "md5(" in line.lower() or "sha1(" in line.lower():
                findings.append({
                    "file": file_path, "line": idx,
                    "cwe": "CWE-327 (Weak Cryptography)", "severity": "Medium",
                    "snippet": line.strip(),
                    "recommendation": "Use SHA-256 or bcrypt for hashing sensitive data."
                })

        # --- AI Deep Analysis via DeepSeek-R1 (original project model) ---
        prompt = f"""You are a senior security code auditor specializing in OWASP Top 10 and CWE vulnerabilities.

Analyze this code from file `{file_path}`:
```
{code_snippet[:1200]}
```

For each vulnerability:
- CWE ID and name
- Severity: Critical / High / Medium / Low
- Affected line number
- Root cause in one sentence
- Specific code fix

If no vulnerabilities found, state "No critical vulnerabilities detected." Be thorough."""

        ai_result = call_llm(prompt, model=MODEL_SAST, max_tokens=700)
        findings.append({
            "file": file_path, "line": "—",
            "cwe": "🧠 DeepSeek-R1 Deep Security Audit",
            "severity": "Analysis Complete",
            "snippet": code_snippet[:80].replace("\n", " ") + "...",
            "recommendation": ai_result
        })
        return findings

    def analyze_repository(self, repo_url: str) -> List[Dict[str, Any]]:
        import tempfile
        import subprocess
        import os
        logger.info(f"Cloning and analyzing repository {repo_url}...")
        findings = []
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                subprocess.run(["git", "clone", "--depth", "1", repo_url, temp_dir], check=True, capture_output=True)
                # Pick a few key files to analyze
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        if file.endswith(('.py', '.js', '.php', '.go', '.java')):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    code = f.read()
                                    if code.strip():
                                        rel_path = os.path.relpath(file_path, temp_dir)
                                        f_findings = self.analyze_source_code(code[:3000], file_path=rel_path)
                                        findings.extend(f_findings)
                            except Exception:
                                pass
            except Exception as e:
                findings.append({"error": f"Failed to clone or analyze repository: {str(e)}"})
        return findings
