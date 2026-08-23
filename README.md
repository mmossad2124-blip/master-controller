---
title: Remediation Dashboard & DevSecOps Platform
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: streamlit
sdk_version: "1.30.0"
app_file: app.py
pinned: false
---

# 🛡️ AI DevSecOps Audit Platform

منصة الفحص والتأمين البرمجي الأوتوماتيكي باستخدام الذكاء الاصطناعي والموزعة سحابياً 100%.

---

## 🏛️ معمارية المشروع الحسابية (Cloud Distribution)

المشروع مصمم ليعمل موزطاً على **3 حسابات سحابية على GitHub و Hugging Face** كالتالي:

1. **الحساب الأول (`mmossad2124@gmail.com`):**
   * **GitHub Repo:** `https://github.com/mmossad2124-blip/master-controller`
   * **Hugging Face Space:** `https://huggingface.co/spaces/Mmossad2124/sast-recon-agent`
2. **الحساب الثاني (`mmossad2224@gmail.com`):**
   * **GitHub Repo:** `https://github.com/mmossad2224-eng/vector-db-state`
   * **Hugging Face Space:** `https://huggingface.co/spaces/Mmossad2224/dast-athena-sandbox`
3. **الحساب الثالث (`mmossad2324@gmail.com`):**
   * **GitHub Repo:** `https://github.com/mmossad2324-cpu/reports-patches-storage`
   * **Hugging Face Space:** `https://huggingface.co/spaces/Mmossad2324/remediation-dashboard` (Streamlit Web Dashboard + Multi-Session)

---

## 📂 هيكل المجلدات والملفات (Directory Structure)

```text
AI-bot-pentast/
├── app.py                         # واجهة لوحة التحكم (Streamlit Web UI + Session Manager)
├── master_orchestrator.py         # المنسق الرئيسي للتأمين وتوزيع المهام
├── config.json                    # إعدادات الحسابات والـ Repos الـ 3
├── requirements.txt               # المكتبات المطلوبة
├── core/
│   ├── sast_agent.py              # محرك فحص الكود الثابت (DeepSeek-R1)
│   ├── dast_agent.py              # محرك الفحص الديناميكي للمتصفح (Athena OS + Playwright)
│   ├── remediation_agent.py       # محرك كتابة الترقيع البرمجي (Tree of Thoughts)
│   └── graph_memory.py            # ذاكرة الرسم البياني (Graph-RAG + ChromaDB)
├── utils/
│   ├── session_manager.py         # إدارة الجلسات المنفصلة وحفظ التاريخ
│   └── cloud_sync.py              # الرفع والتزامن التلقائي على GitHub & HF
```
