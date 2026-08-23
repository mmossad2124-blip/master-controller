"""
DAST Security Inference Server
Model: Mistral-7B-Instruct-v0.2 (GGUF Q4_K_M) via llama-cpp-python
Specializes in: HTTP security headers analysis, attack surface mapping
"""
import os, logging
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from huggingface_hub import hf_hub_download

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DAST-Server")

app = FastAPI(title="DAST Security Inference API", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

MODEL_REPO  = "TheBloke/Mistral-7B-Instruct-v0.2-GGUF"
MODEL_FILE  = "mistral-7b-instruct-v0.2.Q4_K_M.gguf"
MODEL_PATH  = Path("/tmp/model.gguf")
N_CTX, N_THREADS = 4096, 2
llm = None

def load_model():
    global llm
    if llm is not None: return
    logger.info("Downloading Mistral-7B-Instruct GGUF (~4GB)...")
    if not MODEL_PATH.exists():
        hf_hub_download(repo_id=MODEL_REPO, filename=MODEL_FILE,
                        local_dir="/tmp", local_dir_use_symlinks=False)
        Path(f"/tmp/{MODEL_FILE}").rename(MODEL_PATH)
    from llama_cpp import Llama
    llm = Llama(model_path=str(MODEL_PATH), n_ctx=N_CTX,
                n_threads=N_THREADS, n_gpu_layers=0, verbose=False)
    logger.info("✅ Mistral-7B loaded!")

class DASTRequest(BaseModel):
    target_url: str
    headers: dict
    max_tokens: int = 512

class DASTResponse(BaseModel):
    analysis: str
    model: str
    status: str

@app.get("/")
def root():
    return {"status": "DAST Inference Server Running", "model": MODEL_REPO}

@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": llm is not None}

@app.post("/analyze", response_model=DASTResponse)
def analyze_dast(req: DASTRequest):
    load_model()
    headers_text = "\n".join(f"  {k}: {v}" for k, v in req.headers.items())
    prompt = f"""[INST] You are a penetration tester and web security expert.

Analyze these HTTP security headers from target: {req.target_url}

{headers_text}

Provide:
1. Risk assessment for EACH missing security header (explain what attacks it enables)
2. Severity rating per header: Critical/High/Medium/Low
3. Real-world attack scenarios enabled by these gaps
4. Overall security score (0-10)
5. Top 3 most urgent fixes with exact header values to add

Be specific, technical, and actionable. [/INST]"""

    try:
        output = llm(prompt, max_tokens=req.max_tokens, temperature=0.1, echo=False)
        return DASTResponse(analysis=output["choices"][0]["text"].strip(),
                           model="mistral-7b-instruct-v0.2-Q4_K_M", status="success")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
