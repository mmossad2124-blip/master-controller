import streamlit as st
import time
import json
import os
import sys
import uuid
from datetime import datetime

# Ensure imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from server.agent_api import CloudAgentOrchestrator

# Configure page for a sleek chat experience
st.set_page_config(
    page_title="Enterprise AI Agent - SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for a professional dark look
st.markdown("""
<style>
    /* Main background */
    .stApp {
        background-color: #0f172a;
    }
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #1e293b;
        border-right: 1px solid #334155;
    }
    /* Chat bubbles */
    .stChatMessage {
        background-color: transparent;
        border-radius: 10px;
    }
    [data-testid="chatAvatarIcon-user"] {
        background-color: #3b82f6;
    }
    [data-testid="chatAvatarIcon-assistant"] {
        background-color: #10b981;
    }
    /* Input box styling */
    .stChatInputContainer {
        border: 1px solid #334155;
        border-radius: 12px;
        background-color: #1e293b;
    }
    h1, h2, h3 {
        color: #f8fafc;
        font-family: 'Segoe UI', sans-serif;
    }
    /* Hide default Streamlit top menu */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Session button styling */
    .session-btn {
        width: 100%;
        text-align: left;
        padding: 10px;
        background-color: transparent;
        border: none;
        color: #cbd5e1;
        cursor: pointer;
        border-radius: 5px;
        margin-bottom: 5px;
    }
    .session-btn:hover {
        background-color: #334155;
        color: white;
    }
    .session-btn.active {
        background-color: #3b82f6;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- SESSION MANAGEMENT -----------------
SESSIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sessions")
os.makedirs(SESSIONS_DIR, exist_ok=True)

def get_all_sessions():
    sessions = []
    for f in os.listdir(SESSIONS_DIR):
        if f.endswith('.json'):
            try:
                with open(os.path.join(SESSIONS_DIR, f), 'r', encoding='utf-8') as file:
                    data = json.load(file)
                    sessions.append(data)
            except Exception:
                pass
    # Sort by updated_at descending
    sessions.sort(key=lambda x: x.get('updated_at', ''), reverse=True)
    return sessions

def save_session(session_id, title, messages):
    filepath = os.path.join(SESSIONS_DIR, f"{session_id}.json")
    data = {
        "id": session_id,
        "title": title,
        "updated_at": datetime.now().isoformat(),
        "messages": messages
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_session(session_id):
    filepath = os.path.join(SESSIONS_DIR, f"{session_id}.json")
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None

# ----------------- APP STATE -----------------
if "agent" not in st.session_state:
    st.session_state.agent = CloudAgentOrchestrator()

if "current_session_id" not in st.session_state:
    st.session_state.current_session_id = str(uuid.uuid4())
    
if "messages" not in st.session_state:
    st.session_state.messages = [
        {"role": "assistant", "content": "مرحباً! أنا الوكيل الأمني الخاص بك. يمكنك أن تطلب مني فحص رابط (DAST)، أو مراجعة كود (SAST)، أو استخراج حلول أمنية. كيف أساعدك اليوم؟"}
    ]
    
if "session_title" not in st.session_state:
    st.session_state.session_title = "محادثة جديدة"

# ----------------- SIDEBAR -----------------
with st.sidebar:
    st.markdown("## 🛡️ Enterprise SOC")
    st.markdown("<p style='color: #94a3b8; font-size: 0.9em; margin-bottom: 20px;'>مساحة العمل الآمنة للوكيل الذكي</p>", unsafe_allow_html=True)
    
    if st.button("➕ محادثة جديدة (New Scan)", use_container_width=True, type="primary"):
        st.session_state.current_session_id = str(uuid.uuid4())
        st.session_state.messages = [
            {"role": "assistant", "content": "مرحباً! كيف أساعدك في هذا الفحص الجديد؟"}
        ]
        st.session_state.session_title = "محادثة جديدة"
        st.rerun()
        
    st.markdown("<hr style='border-color: #334155;'>", unsafe_allow_html=True)
    st.markdown("### المحادثات السابقة")
    
    # Load and display sessions
    all_sessions = get_all_sessions()
    if not all_sessions:
        st.markdown("<p style='color: #64748b; font-size: 0.8em;'>لا يوجد فحوصات سابقة.</p>", unsafe_allow_html=True)
    else:
        for sess in all_sessions:
            sess_id = sess.get('id')
            if not sess_id: continue
            
            is_active = (sess_id == st.session_state.current_session_id)
            btn_style = "primary" if is_active else "secondary"
            if st.button(f"💬 {sess.get('title', 'محادثة')}", key=f"btn_{sess_id}", use_container_width=True, type=btn_style):
                st.session_state.current_session_id = sess_id
                st.session_state.messages = sess.get('messages', [])
                st.session_state.session_title = sess.get('title', 'محادثة')
                st.rerun()


# ----------------- MAIN WORKSPACE -----------------
col_chat, col_terminal = st.columns([0.65, 0.35], gap="large")

with col_terminal:
    st.markdown("### 🖥️ Live Agent Terminal")
    st.markdown("<p style='color: #64748b; font-size: 0.8em;'>يعرض طريقة التفكير وتشغيل الأدوات بشكل حي</p>", unsafe_allow_html=True)
    terminal_placeholder = st.empty()
    
    if "terminal_logs" not in st.session_state:
        st.session_state.terminal_logs = "Agent Initialized...\nWaiting for commands...\n"
        
    terminal_placeholder.code(st.session_state.terminal_logs, language="bash")

with col_chat:
    st.title(f"🔍 {st.session_state.session_title}")

    # Display Chat History
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Handle User Input
    if prompt := st.chat_input("اكتب أمرك هنا... (مثال: افحص الرابط كذا)"):
        # Generate a title for new sessions based on the first prompt
        if len(st.session_state.messages) <= 1:
            st.session_state.session_title = prompt[:30] + "..." if len(prompt) > 30 else prompt

        # Add user message to state and display
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
            
        save_session(st.session_state.current_session_id, st.session_state.session_title, st.session_state.messages)

        # Callback to update terminal live
        def update_terminal(msg):
            st.session_state.terminal_logs += f"{msg}\n"
            terminal_placeholder.code(st.session_state.terminal_logs, language="bash")

        # Process via Agent
        with st.chat_message("assistant"):
            with st.spinner("🧠 الوكيل المستقل يحلل طلبك ويستدعي الأدوات اللازمة..."):
                try:
                    # Clear terminal for new run
                    st.session_state.terminal_logs = "---------------------------------\n"
                    st.session_state.terminal_logs += f"[User Prompt]: {prompt}\n[Agent]: Starting analysis...\n"
                    terminal_placeholder.code(st.session_state.terminal_logs, language="bash")

                    # Call the Agent Orchestrator with callback
                    response = st.session_state.agent.process_intent(prompt, log_callback=update_terminal)
                    st.markdown(response)
                    st.session_state.messages.append({"role": "assistant", "content": response})
                    
                    save_session(st.session_state.current_session_id, st.session_state.session_title, st.session_state.messages)
                except Exception as e:
                    err_msg = f"حدث خطأ أثناء الاتصال بالنماذج: {str(e)}"
                    st.error(err_msg)
                    st.session_state.messages.append({"role": "assistant", "content": err_msg})
                    save_session(st.session_state.current_session_id, st.session_state.session_title, st.session_state.messages)
