from datetime import datetime
import os
import pandas as pd
import requests

API_KEY_FILE = "api_key.txt"
GEMINI_MODEL = "gemini-2.5-pro"  # You can change model name if needed
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

# ---------------------- API Key Handling ----------------------
def save_api_key(api_key):
    with open(API_KEY_FILE, "w") as f:
        f.write(api_key)
    print("API key saved.")
    print("------------------------------------------------------------")

def load_api_key():
    if os.path.isfile(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as f:
            return f.read().strip()
    return None

# ---------------------- CSV Filtering ----------------------
def prepare_csv_for_gemini(df):
    # Columns to keep for rule generation
    columns_to_keep = ['Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Prediction',
                       'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
                       'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std',
                       'SYN Flag Cnt', 'ACK Flag Cnt', 'FIN Flag Cnt', 'RST Flag Cnt',
                       'PSH Flag Cnt', 'URG Flag Cnt',
                       'Flow Byts/s', 'Flow Pkts/s',
                       'Flow IAT Mean', 'Flow IAT Std', 'Down/Up Ratio',
                       'Init Fwd Win Byts', 'Init Bwd Win Byts']

    df_filtered = df[columns_to_keep]

    final_dfs = []
    for attack_type in df_filtered['Prediction'].unique():
        attack_df = df_filtered[df_filtered['Prediction'] == attack_type]
        attack_df = attack_df.drop_duplicates(subset=['Src IP'])
        limited_df = attack_df.head(50)
        final_dfs.append(limited_df)

    result_df = pd.concat(final_dfs)
    return result_df

# ---------------------- Gemini API Call ----------------------
def send_to_gemini_api(api_key, csv_path):
    with open(csv_path, 'r', encoding='utf-8') as f:
        csv_content = f.read()

    # Enrich prompt with explanation of features to consider for better rules
    prompt = (
    "You are a senior cybersecurity expert with over 10 years of experience specializing in writing accurate and production-ready detection rules "
    "for Suricata and Snort. You are highly skilled in analyzing network flow data and creating both generalized and flow-specific rules.\n\n"

    "Your task is to analyze the provided CSV flow data and generate two types of rules based strictly on the information it contains:\n\n"

    "1. GENERAL RULES (One per attack type):\n"
    "- For each unique attack type found in the 'Prediction' column of the CSV, analyze ALL related flow entries.\n"
    "- Extract shared behaviors and flow characteristics (e.g., protocol, flags, byte rates, flow duration, etc.).\n"
    "- Use these to create one generalized and reusable rule for that attack type.\n"
    "- DO NOT include specific IP addresses or ports.\n"
    "- ONLY generate a general rule if the shared characteristics are clear and consistent across multiple flows.\n"
    "- If no reliable pattern can be found, DO NOT generate a general rule for that type.\n"
    "- DO NOT generate rules for attack types that do not exist in the CSV.\n\n"

    "2. SPECIFIC RULES (One per flow entry):\n"
    "- For each row in the CSV, create a rule using its source/destination IPs, ports, protocol, and any flow-specific attributes from that row.\n"
    "- Use the same detection logic as the general rule for its attack type when possible.\n"
    "- If the flow does not contain enough meaningful data to construct a valid and logical rule, skip it.\n"
    "- DO NOT generate rules for flow entries with attack types that do not exist in the CSV.\n\n"

    "RULE QUALITY REQUIREMENTS:\n"
    "- ONLY output rules that are realistic, valid, and logically consistent with the flow data.\n"
    "- DO NOT guess or invent values (e.g., fake content strings or impossible flags).\n"
    "- DO NOT output generic or placeholder rules.\n"
    "- If you cannot confidently generate a useful rule for a flow or attack type, omit it.\n\n"

    "USE THE FOLLOWING FLOW FEATURES WHEN RELEVANT:\n"
    "- Flow Duration\n"
    "- Total Forward and Backward Packets\n"
    "- Packet Length (min, max, mean, std)\n"
    "- TCP Flag counts (SYN, ACK, FIN, RST, PSH, URG, CWE, ECE)\n"
    "- Byte and Packet rates\n"
    "- Inter-arrival times (mean, std, max, min)\n"
    "- Segment sizes\n"
    "- Down/Up Ratio\n"
    "- Initial Fwd and Bwd Window Sizes\n\n"

    "RULE FORMAT AND OUTPUT INSTRUCTIONS:\n"
    "- Output only rules in the user-selected format (Snort or Suricata).\n"
    "- First, output one general rule per unique attack type found in the CSV (if valid).\n"
    "- Then, output one specific rule per flow entry (if valid).\n"
    "- DO NOT include explanations, comments, markdown, or any extra text.\n"
    "- DO NOT wrap rules in code blocks.\n"
    "- DO NOT output anything other than valid rules.\n"
    "- DO NOT create rules for attacks or categories that are not present in the 'Prediction' column of the CSV.\n\n"

    "REMEMBER:\n"
    "- It is better to SKIP a rule than to generate something unrealistic or syntactically invalid.\n"
    "- Be conservative and careful — these rules are for use in real-world intrusion detection systems.\n\n"

    "Input CSV data:\n"
    "{csv_content}"
)





    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [
            {"parts": [{"text": prompt}]}
        ]
    }

    print("Sending CSV with up to 50 flows per attack to Gemini API...")
    response = requests.post(
        f"{GEMINI_API_URL}?key={api_key}",
        headers=headers,
        json=payload
    )

    if response.status_code == 200:
        print("Gemini API responded successfully.")
        rules_text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
        print("Generated Rules:")
        print(rules_text)
        print("------------------------------------------------------------")
        

        # Save to unique file
        rules_dir = "Rules"
        os.makedirs(rules_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rules_filename = f"generated_rules_{timestamp}.rules"
        rules_path = os.path.join(rules_dir, rules_filename)

        with open(rules_path, "w", encoding="utf-8") as f:
            f.write(rules_text)

        print(f"[INFO] Rules saved to {rules_path}")
    else:
        print(f"[ERROR] Gemini API failed: {response.status_code} -> {response.text}")

# ---------------------- Menu & Flow ----------------------
def generate_rules():
    print("Rule Generator Menu:")
    print("1 - Suricata")
    print("2 - Snort")
    choice = input("Enter your choice: ").strip()
    if choice not in ['1', '2']:
        print("Invalid choice, returning to main menu.")
        return

    api_opt = input("Do you want to enter/modify API key? (Y/N): ").strip().upper()
    if api_opt == 'Y':
        api_key = input("Enter API key: ").strip()
        save_api_key(api_key)
    elif api_opt != 'N':
        print("Invalid input. Returning to main menu.")
        return

    api_key = load_api_key()
    if api_key is None:
        print("No API key found. Please enter it first by choosing 'Y' in API prompt.")
        return

    filename = input("Enter CSV file name (without path) from /CSVs/malicious/: ").strip()
    csv_file = os.path.join("CSVs", "malicious", filename)
    if not os.path.isfile(csv_file):
        print(f"CSV file {csv_file} does not exist.")
        return

    df = pd.read_csv(csv_file)
    required_cols = ['Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Prediction']
    for col in required_cols:
        if col not in df.columns:
            print(f"CSV missing required column: {col}")
            return

    gemini_df = prepare_csv_for_gemini(df)

    temp_csv = "temp_gemini_input.csv"
    gemini_df.to_csv(temp_csv, index=False)

    send_to_gemini_api(api_key, temp_csv)

    os.remove(temp_csv)

if __name__ == "__main__":
    generate_rules()
