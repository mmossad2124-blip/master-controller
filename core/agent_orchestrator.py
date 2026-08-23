import json
import logging
from typing import Dict, Any, List
from core.llm_client import call_cf_workers_ai, MODEL_SAST, MODEL_REMEDIATION

logger = logging.getLogger("AgentOrchestrator")

class AgentOrchestrator:
    """Intelligent Agent Orchestrator inspired by HexStrike's MCP architecture.
    It takes user intents and uses CF Workers AI (DeepSeek/GLM) to decide which defensive tools to call.
    """

    def __init__(self):
        self.available_tools = {
            "run_sast": {
                "name": "run_sast",
                "description": "Run Static Application Security Testing (SAST) on provided source code to find vulnerabilities.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The source code to analyze."}
                    },
                    "required": ["code"]
                }
            },
            "run_dast": {
                "name": "run_dast",
                "description": "Run Dynamic Application Security Testing (DAST) to inspect HTTP headers and API security.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "The URL of the target application."}
                    },
                    "required": ["target_url"]
                }
            },
            "generate_patch": {
                "name": "generate_patch",
                "description": "Generate a secure code patch and WAF rules for a identified vulnerability.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "issue_description": {"type": "string", "description": "Description of the vulnerability."}
                    },
                    "required": ["issue_description"]
                }
            }
        }

    def _execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Execute the requested tool."""
        logger.info(f"Agent executing tool: {tool_name}")
        
        if tool_name == "run_sast":
            from core.sast_agent import SASTAgent
            code = arguments.get("code", "")
            if not code: return "Error: No code provided."
            res = SASTAgent().analyze_source_code(code)
            return json.dumps(res, ensure_ascii=False)
            
        elif tool_name == "run_dast":
            from app import run_full_real_scan
            target_url = arguments.get("target_url", "")
            if not target_url: return "Error: No target_url provided."
            # We use a dummy session_id for the orchestrated standalone test
            res = run_full_real_scan(target_url, "agent-temp-session")
            return f"DAST execution completed. Findings: {len(res.get('enriched_findings', []))}"
            
        elif tool_name == "generate_patch":
            from core.remediation_agent import RemediationAgent
            issue = arguments.get("issue_description", "")
            res = RemediationAgent().generate_patch({"cwe": "Unknown", "severity": "High", "file": "unknown", "snippet": issue})
            return res.get("patch_code", "Failed to generate patch.")
            
        else:
            return f"Error: Tool {tool_name} not found."

    def process_intent(self, user_prompt: str, context: str = "") -> str:
        """Process user intent via Tool-Calling Loop (ReAct style)."""
        tools_desc = json.dumps(list(self.available_tools.values()), ensure_ascii=False, indent=2)
        
        system_prompt = f"""أنت وكيل ذكي مستقل (Autonomous Security Agent).
لديك إمكانية الوصول إلى الأدوات التالية:
{tools_desc}

يجب عليك تحليل طلب المستخدم، وإذا كان الطلب يتطلب فحص رابط، قم بإرجاع JSON فقط يحتوي على استدعاء الأداة المطلوبة بهذا التنسيق:
```json
{{"action": "tool_name", "arguments": {{"arg_name": "arg_value"}}}}
```
وإذا كان الطلب مجرد استفسار، أجب باللغة العربية مباشرة.
"""
        
        # Step 1: Ask LLM what to do
        response = call_cf_workers_ai(user_prompt, model_index=0, system_prompt=system_prompt)
        
        # Step 2: Parse if it's a tool call
        try:
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            else:
                json_str = response
                
            action_req = json.loads(json_str)
            if "action" in action_req and "arguments" in action_req:
                tool_name = action_req["action"]
                tool_args = action_req["arguments"]
                
                # Step 3: Execute Tool
                tool_result = self._execute_tool(tool_name, tool_args)
                
                # Step 4: Final Summary
                final_prompt = f"المستخدم طلب: {user_prompt}\nنتيجة تنفيذ الأداة ({tool_name}): {tool_result[:1000]}\nقم بصياغة رد نهائي احترافي باللغة العربية للمستخدم."
                final_answer = call_cf_workers_ai(final_prompt, model_index=1, system_prompt="أنت مساعد أمني ذكي.")
                return f"🛠️ **إجراء الوكيل المستقل (Agent Action):** تم استدعاء الأداة `{tool_name}`.\n\n{final_answer}"
                
        except Exception as e:
            # Not a tool call, just return the direct answer
            pass
            
        return response
