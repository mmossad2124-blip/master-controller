import json
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional

SESSIONS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sessions")

class SessionManager:
    """Manages isolated audit/chat sessions to prevent cross-contamination."""

    def __init__(self, sessions_dir: str = SESSIONS_DIR):
        self.sessions_dir = sessions_dir
        os.makedirs(self.sessions_dir, exist_ok=True)

    def create_session(self, project_name: str, target_url: Optional[str] = None) -> Dict:
        session_id = str(uuid.uuid4())
        session_data = {
            "session_id": session_id,
            "project_name": project_name,
            "target_url": target_url or "",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "chat_history": [],
            "sast_results": [],
            "dast_results": [],
            "remediation_patches": []
        }
        self.save_session(session_data)
        return session_data

    def save_session(self, session_data: Dict) -> None:
        session_id = session_data["session_id"]
        session_data["updated_at"] = datetime.utcnow().isoformat()
        filepath = os.path.join(self.sessions_dir, f"{session_id}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(session_data, f, indent=2, ensure_ascii=False)

    def load_session(self, session_id: str) -> Optional[Dict]:
        filepath = os.path.join(self.sessions_dir, f"{session_id}.json")
        if not os.path.exists(filepath):
            return None
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def list_sessions(self) -> List[Dict]:
        sessions = []
        if not os.path.exists(self.sessions_dir):
            return sessions
        for filename in os.listdir(self.sessions_dir):
            if filename.endswith(".json"):
                session_id = filename.replace(".json", "")
                data = self.load_session(session_id)
                if data:
                    sessions.append({
                        "session_id": data.get("session_id", data.get("id", session_id)),
                        "project_name": data.get("project_name", data.get("title", "Untitled")),
                        "target_url": data.get("target_url", ""),
                        "created_at": data.get("created_at", data.get("updated_at", "")),
                        "updated_at": data.get("updated_at", "")
                    })
        sessions.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
        return sessions

    def add_message(self, session_id: str, role: str, content: str) -> None:
        session = self.load_session(session_id)
        if session:
            session["chat_history"].append({
                "role": role,
                "content": content,
                "timestamp": datetime.utcnow().isoformat()
            })
            self.save_session(session)
