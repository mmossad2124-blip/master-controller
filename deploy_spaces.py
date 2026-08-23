#!/usr/bin/env python3
"""Deploy all 3 HF Spaces with local model inference servers."""
import os, logging, shutil
from pathlib import Path
from huggingface_hub import HfApi

import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SpaceDeploy")

BASE = Path(__file__).parent
SECRETS_FILE = BASE / ".secrets.json"

def get_secrets():
    if SECRETS_FILE.exists():
        with open(SECRETS_FILE) as f:
            return json.load(f)
    return {}

secrets = get_secrets()

SPACES = [
    {
        "user_key":   "mmossad2124-blip",
        "user":       "Mmossad2124",
        "space_name": "sast-recon-agent",
        "local_dir":  "hf_spaces/sast-space",
        "description":"SAST engine - DeepSeek-Coder-6.7B runs locally on this Space"
    },
    {
        "user_key":   "mmossad2224-eng",
        "user":       "Mmossad2224",
        "space_name": "dast-athena-sandbox",
        "local_dir":  "hf_spaces/dast-space",
        "description":"DAST engine - GLM-4 runs locally on this Space"
    },
    {
        "user_key":   "mmossad2324-cpu",
        "user":       "Mmossad2324",
        "space_name": "remediation-dashboard",
        "local_dir":  "hf_spaces/remediation-space",
        "description":"Remediation engine - GLM-4 runs locally on this Space"
    },
]

for sp in SPACES:
    token = secrets.get(sp["user_key"], {}).get("hf", "")
    sp["token"] = token


BASE = Path(__file__).parent

for sp in SPACES:
    repo_id = f"{sp['user']}/{sp['space_name']}"
    logger.info(f"\n=== Deploying {repo_id} ===")
    api = HfApi(token=sp["token"])

    # Create or ensure space exists
    try:
        api.create_repo(repo_id=repo_id, repo_type="space",
                        space_sdk="docker", exist_ok=True,
                        private=False)
        logger.info(f"Space {repo_id} ready.")
    except Exception as e:
        logger.warning(f"Space create: {e}")

    # Upload all files
    local = BASE / sp["local_dir"]
    for fpath in local.rglob("*"):
        if fpath.is_file():
            rel = fpath.relative_to(local)
            logger.info(f"  Uploading {rel}...")
            api.upload_file(
                path_or_fileobj=str(fpath),
                path_in_repo=str(rel),
                repo_id=repo_id,
                repo_type="space",
            )
    logger.info(f"✅ {repo_id} deployed → https://huggingface.co/spaces/{repo_id}")

print("\n=== All 3 inference Spaces deployed! ===")
print("URLs:")
for sp in SPACES:
    print(f"  https://{sp['user'].lower()}-{sp['space_name']}.hf.space/health")
