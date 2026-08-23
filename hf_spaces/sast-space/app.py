"""
SAST Security Inference API — Gradio Space
Model: DeepSeek-Coder-6.7B-Instruct GGUF Q4_K_M (runs locally on HF CPU)
RAM needed: ~4GB of 16GB available
Inference speed: 15-30 seconds on CPU
"""
import os, logging
from pathlib import Path
import gradio as gr
from huggingface_hub import hf_hub_download

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SAST")

MODEL_REPO = "TheBloke/deepseek-coder-6.7B-instruct-GGUF"
MODEL_FILE = "deepseek-coder-6.7b-instruct.Q4_K_M.gguf"
MODEL_PATH = Path("/tmp/deepseek-coder.gguf")

llm = None

def load_model():
    global llm
    if llm is not None:
        return "✅ Model already loaded"
    logger.info("Downloading DeepSeek-Coder-6.7B Q4_K_M...")
    if not MODEL_PATH.exists():
        hf_hub_download(repo_id=MODEL_REPO, filename=MODEL_FILE,
                        local_dir="/tmp", local_dir_use_symlinks=False)
        downloaded = Path(f"/tmp/{MODEL_FILE}")
        if downloaded.exists():
            downloaded.rename(MODEL_PATH)
    from llama_cpp import Llama
    llm = Llama(model_path=str(MODEL_PATH), n_ctx=4096,
                n_threads=2, n_gpu_layers=0, verbose=False)
    logger.info("✅ DeepSeek-Coder loaded!")
    return "✅ Model loaded"

def analyze_code(code: str, file_path: str = "app.py") -> str:
    """Analyze source code for security vulnerabilities."""
    if not code.strip():
        return "⚠️ No code provided."
    load_model()
    if llm is None:
        return "❌ Model failed to load."
    
    prompt = f"""You are an expert cybersecurity code auditor (OWASP Top 10, CWE).
Analyze this code from `{file_path}` for security vulnerabilities:

```python
{code[:2000]}
```

For each vulnerability:
1. CWE ID and name
2. Severity: Critical/High/Medium/Low
3. Line number
4. Root cause
5. Exact secure fix

If none found: "No critical vulnerabilities detected."
"""
    output = llm(prompt, max_tokens=600, temperature=0.1, echo=False)
    return output["choices"][0]["text"].strip()

# Gradio interface (also serves as API endpoint)
with gr.Blocks(title="SAST Security Agent") as demo:
    gr.Markdown("# 🔍 SAST Security Agent\nDeepSeek-Coder-6.7B running locally on this Space")
    with gr.Row():
        code_input = gr.Textbox(label="Source Code", lines=15, placeholder="Paste code here...")
        file_input = gr.Textbox(label="File Path", value="app.py")
    analyze_btn = gr.Button("🔍 Analyze Security", variant="primary")
    output = gr.Textbox(label="Security Analysis", lines=20)
    analyze_btn.click(analyze_code, inputs=[code_input, file_input], outputs=output)

# Also expose as REST API via gradio's built-in /api/predict
if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
