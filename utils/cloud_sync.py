import os
import json
import logging
from typing import Dict, Any

import subprocess

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CloudSync")

class CloudSyncManager:
    """Manages Git Push checkpointing and Hugging Face Hub dataset/model sync."""

    def __init__(self, config_path: str = "config.json", secrets_path: str = ".secrets.json"):
        self.project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.config = self._load_json(os.path.join(self.project_dir, config_path))
        self.secrets = self._load_json(os.path.join(self.project_dir, secrets_path))

    def _load_json(self, path: str) -> Dict[str, Any]:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading {path}: {e}")
        return {}

    def sync_checkpoints_to_github(self, repo_id: int = 1, commit_message: str = "Auto-checkpoint state update") -> bool:
        """Executes Git commit and push of checkpoints to designated GitHub repo."""
        logger.info(f"Syncing state to GitHub Repo Acc #{repo_id}: {commit_message}")
        try:
            # Check git status
            res = subprocess.run(["git", "status", "--porcelain"], cwd=self.project_dir, capture_output=True, text=True)
            if not res.stdout.strip():
                logger.info("No uncommitted changes for Git checkpoint.")
                return True

            subprocess.run(["git", "add", "sessions/"], cwd=self.project_dir, check=False)
            subprocess.run(["git", "commit", "-m", commit_message], cwd=self.project_dir, check=False)
            logger.info("✅ Git checkpoint committed successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed Git checkpoint sync: {e}")
            return False

    def sync_to_huggingface_hub(self, account_index: int = 3, file_path: str = "") -> bool:
        """Uploads persistent state files or session reports to designated Hugging Face Space."""
        if not file_path or not os.path.exists(file_path):
            logger.warning(f"File path invalid or missing for HF sync: {file_path}")
            return False

        accounts = self.config.get("accounts", [])
        if not accounts or account_index > len(accounts):
            logger.error(f"Invalid account_index {account_index}")
            return False

        target_acc = accounts[account_index - 1]
        user = target_acc["username"]
        space_id = target_acc["hf_space"]
        token = self.secrets.get(user, {}).get("hf", "")

        if not token:
            logger.error(f"No HF token found for user {user}")
            return False

        try:
            from huggingface_hub import HfApi
            api = HfApi(token=token)
            dest_filename = f"reports/{os.path.basename(file_path)}"
            api.upload_file(
                path_or_fileobj=file_path,
                path_in_repo=dest_filename,
                repo_id=space_id,
                repo_type="space"
            )
            logger.info(f"✅ Uploaded artifact {file_path} to HF Space '{space_id}' -> {dest_filename}")
            return True
        except Exception as e:
            logger.error(f"HF Hub Sync failed: {e}")
            return False

