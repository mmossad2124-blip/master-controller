"""
Remediation Inference Server
Model: Mistral-7B-Instruct-v0.2 (GGUF Q4_K_M) - Tree of Thoughts patching
Specializes in: Secure code fixes, ModSecurity WAF rules, vulnerability patches
"""
import os, logging
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from huggingface_hub import hf_hub_download

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Remediation-Server")

app = FastAPI(title="Remediation Inference API", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

MODEL_REPO  = "TheBloke/Mistral-7B-Instruct-v0.2-GGUF"
MODEL_FILE  = "mistral-7b-instruct-v0.2.Q4_K_M.gguf"
MODEL_PATH  = Path("/tmp/model.gguf")
N_CTX, N_THREADS = 4096, 2
llm = None

def load_model():
    global llm
    if llm is not None: return
    logger.info("Downloading Mistral-7B GGUF for remediation...")
    if not MODEL_PATH.exists():
        hf_hub_download(repo_id=MODEL_REPO, filename=MODEL_FILE,
                        local_dir="/tmp", local_dir_use_symlinks=False)
        Path(f"/tmp/{MODEL_FILE}").rename(MODEL_PATH)
    from llama_cpp import Llama
    llm = Llama(model_path=str(MODEL_PATH), n_ctx=N_CTX,
                n_threads=N_THREADS, n_gpu_layers=0, verbose=False)
    logger.info("✅ Mistral-7B Remediation engine loaded!")

class PatchRequest(BaseModel):
    cwe: str
    severity: str
    file_path: str
    snippet: str
    max_tokens: int = 600

class PatchResponse(BaseModel):
    patch: str
    waf_rule: str
    model: str
    status: str

@app.get("/")
def root():
    return {"status": "Remediation Inference Server Running", "model": MODEL_REPO}

@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": llm is not None}

@app.post("/patch", response_model=PatchResponse)
def generate_patch(req: PatchRequest):
    load_model()
    prompt = f"""[INST] You are a senior security engineer using Tree-of-Thoughts reasoning to fix vulnerabilities.

Vulnerability:
- CWE: {req.cwe}
- Severity: {req.severity}
- File: {req.file_path}
- Vulnerable code:
```
{req.snippet}
```

Step 1 - ROOT CAUSE: Explain exactly why this code is vulnerable in 1-2 sentences.
Step 2 - SECURE FIX: Write the complete patched version of the vulnerable code.
Step 3 - WAF RULE: Write a ModSecurity rule to block exploitation at the network level.
Step 4 - VERIFICATION: One command or test to verify the fix works.

Be production-ready and precise. [/INST]"""

    try:
        output = llm(prompt, max_tokens=req.max_tokens, temperature=0.05, echo=False)
        text = output["choices"][0]["text"].strip()
        waf = (f'SecRule ARGS "@detectSQLi" '
               f'"id:10001,phase:2,deny,status:403,log,msg:\'{req.cwe} Blocked\'"')
        return PatchResponse(patch=text, waf_rule=waf,
                            model="mistral-7b-instruct-v0.2-Q4_K_M", status="success")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
