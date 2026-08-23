import os
import json
import requests
import subprocess
import shutil
import logging
from huggingface_hub import HfApi

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CloudDeploy")

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(PROJECT_DIR, "config.json")
SECRETS_PATH = os.path.join(PROJECT_DIR, ".secrets.json")

def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def load_secrets():
    if os.path.exists(SECRETS_PATH):
        with open(SECRETS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def run_cmd(cmd, cwd=PROJECT_DIR):
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, shell=isinstance(cmd, str))
    return res

def reset_clean_git_repo():
    git_dir = os.path.join(PROJECT_DIR, ".git")
    if os.path.exists(git_dir):
        shutil.rmtree(git_dir)
    run_cmd("git init")
    run_cmd("git config user.name 'DevSecOps-Deployer'")
    run_cmd("git config user.email 'devsecops@platform.local'")
    run_cmd("git add .")
    run_cmd("git commit -m 'Initial AI DevSecOps Platform Deployment'")
    run_cmd("git branch -M main")

def deploy_to_github(acc: dict, secrets: dict):
    username = acc["username"]
    token = secrets.get(username, {}).get("github", "")
    repo_url = acc["github_repo"]
    repo_name = repo_url.split("/")[-1]

    if not token:
        logger.error(f"No GitHub token found for {username}")
        return

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    logger.info(f"Checking GitHub repo '{username}/{repo_name}'...")
    check_resp = requests.get(f"https://api.github.com/repos/{username}/{repo_name}", headers=headers)
    if check_resp.status_code == 404:
        logger.info(f"Creating GitHub repo '{username}/{repo_name}'...")
        requests.post("https://api.github.com/user/repos", headers=headers, json={
            "name": repo_name,
            "private": False,
            "auto_init": False
        })

    authenticated_remote = f"https://{username}:{token}@github.com/{username}/{repo_name}.git"
    remote_name = f"origin_{username}"

    run_cmd(f"git remote remove {remote_name}")
    run_cmd(f"git remote add {remote_name} {authenticated_remote}")

    logger.info(f"Pushing code to GitHub repo '{username}/{repo_name}'...")
    push_res = run_cmd(f"git push {remote_name} main --force --no-verify")
    if push_res.returncode == 0:
        logger.info(f"✅ Successfully pushed to GitHub: https://github.com/{username}/{repo_name}")
    else:
        logger.error(f"❌ Git push failed for {username}: {push_res.stderr.strip()}")

def deploy_to_huggingface(acc: dict, secrets: dict):
    username = acc["username"]
    hf_token = secrets.get(username, {}).get("hf", "")
    space_id = acc["hf_space"]

    if not hf_token:
        logger.error(f"No HF token found for {username}")
        return

    api = HfApi(token=hf_token)
    logger.info(f"Checking Hugging Face Space '{space_id}'...")

    try:
        api.create_repo(
            repo_id=space_id,
            repo_type="space",
            space_sdk="docker",
            exist_ok=True,
            private=False
        )
        logger.info(f"Hugging Face Space '{space_id}' ready. Uploading files...")

        api.upload_folder(
            folder_path=PROJECT_DIR,
            repo_id=space_id,
            repo_type="space",
            ignore_patterns=["sessions/*", ".git/*", "__pycache__/*", "*.pyc", ".secrets.json"]
        )
        logger.info(f"✅ Successfully uploaded to Hugging Face Space: https://huggingface.co/spaces/{space_id}")
    except Exception as e:
        logger.error(f"❌ Error deploying to Hugging Face Space '{space_id}': {str(e)}")

def main():
    config = load_config()
    secrets = load_secrets()
    accounts = config.get("accounts", [])
    logger.info(f"Starting clean deployment across {len(accounts)} accounts...")

    # Reset git history to ensure no secrets in git history
    reset_clean_git_repo()

    for acc in accounts:
        logger.info(f"=== Deploying Account #{acc['id']} ({acc['email']}) ===")
        deploy_to_github(acc, secrets)
        deploy_to_huggingface(acc, secrets)

    logger.info("=== Deployment Process Completed ===")

if __name__ == "__main__":
    main()
