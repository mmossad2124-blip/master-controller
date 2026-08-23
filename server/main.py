from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import os
import uvicorn
from server.agent_api import CloudAgentOrchestrator

app = FastAPI(title="Mossad Ethical Hacker - Enterprise API Agent Server")

# Serve the mobile-first frontend
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def get_ui():
    """Serve the main Mobile/Web UI."""
    ui_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(ui_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.post("/api/v1/scan")
async def trigger_scan(target_url: str):
    """API endpoint to trigger a quick scan via HTTP."""
    agent = CloudAgentOrchestrator()
    res = agent.process_intent(f"افحص لي الرابط: {target_url}")
    return {"status": "success", "agent_response": res}

@app.websocket("/ws/agent")
async def agent_websocket(websocket: WebSocket):
    """Real-time Agent Interaction via WebSockets."""
    await websocket.accept()
    agent = CloudAgentOrchestrator()
    try:
        while True:
            data = await websocket.receive_text()
            # Send immediate feedback that the agent is thinking
            await websocket.send_json({"type": "status", "message": "🧠 الوكيل المستقل يحلل طلبك ويستدعي الأدوات اللازمة..."})
            
            # Process the intent
            reply = agent.process_intent(data)
            
            # Send the final response
            await websocket.send_json({"type": "message", "message": reply})
            
    except WebSocketDisconnect:
        print("Client disconnected.")
    except Exception as e:
        print(f"Error: {e}")
        try:
            await websocket.send_json({"type": "error", "message": f"حدث خطأ داخلي: {str(e)}"})
        except:
            pass

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=7860)
