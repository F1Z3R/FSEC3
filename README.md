# 🔐 AI-Driven Intrusion Detection & Rule Generation Tool

## 📌 Overview  
This project is an **AI-powered Intrusion Detection System (IDS) assistant** that integrates machine learning with automated rule generation.  
It is designed with **modularity, extensibility, and real-world applicability**, making it suitable for both research and SOC (Security Operations Center) environments.  

The tool consists of three main modules:  
1. **Detection Module** – Flow-based traffic classification using ML.  
2. **Rule Generator Module** – Automated Snort/Suricata rule creation.  
3. **Retraining Module** – Continuous model improvement via incremental learning.  

---

## ⚙️ Features  
✅ Flow-based detection from PCAP or CSV (Random Forest & XGBoost)  
✅ Multi-class classification: `BENIGN`, `DoS`, `DDoS`, `Port Scan`, `Web Attack`  
✅ Real-time or offline traffic analysis  
✅ Automated IDS rule generation for **Snort** and **Suricata**  
✅ Optional **LLM integration (Gemini / ChatGPT API)** for refined rule creation  
✅ Feedback loop with **warm-start retraining** to adapt to new threats  

---

## 🏗️ Architecture  

### 🔍 Detection Module  
- Processes PCAP or pre-extracted flow data  
- Extracts CICFlowMeter-like features  
- Applies ML classifiers (Random Forest, XGBoost)  
- Outputs a CSV file with predictions  

### 🛡️ Rule Generator Module  
- Extracts malicious flow attributes (IP, port, protocol, attack type)  
- Generates **Snort/Suricata rules** automatically  
- Saves structured `.rules` file for direct IDS integration  
- Can leverage **Gemini/ChatGPT API** to refine rule syntax  

### 🔄 Retraining Module  
- Collects user feedback in `FP.csv`  
- Performs **warm-start retraining** without losing existing model knowledge  
- Ensures adaptability to evolving attack patterns  

---

## 🚀 Getting Started  

### 📦 Prerequisites  
- Python 3.8+  
- Required libraries:  
```bash
pip install pandas scikit-learn xgboost joblib requests
# Usage
./python3 tool.py  //make sure to be in the /code folder

## 📈 Future Enhancements  

- ⚡ **Real-Time Deployment** – Extend the system from offline post-analysis to real-time traffic monitoring and dynamic rule enforcement.  
- 🧠 **Advanced Machine Learning** – Explore deep learning models such as LSTMs and Transformers for detecting complex and evolving attack patterns.  
- 🔗 **SOC Automation Integration** – Connect with SIEM and SOAR platforms to enable end-to-end automation of detection, triage, and response.  
- 📊 **User Interface Development** – Build an analyst-oriented dashboard with:  
  - Main dashboard for detection analysis  
  - Rule Generator section  
  - Support & FAQ sections  
  - Future Features section  

- 🌍 **Community Contributions** – Enable users to share generated rules and models, fostering a collaborative ecosystem of AI-driven threat intelligence.  
- 🤖 **Dedicated LLM for Rule Generation** – Develop a specialized Large Language Model trained on network traffic patterns, Snort/Suricata rules, and labeled datasets.  
  - Provides context-aware and explainable rule suggestions  
  - Reduces dependency on third-party APIs  
  - Opens opportunities for community-driven fine-tuning and continuous improvement  

