import os
import pandas as pd
import subprocess

def run_detector(pcap_file):
    while True:
        second_arg = input("Enter second argument for Manager.py (win / lin): ").strip().lower()
        if second_arg in ['win', 'lin']:
            break
        else:
            print("Invalid input. Please enter 'win' or 'lin'.")

    cmd = ["python3", "./Manager.py", pcap_file, second_arg]

    print(f"Running detection command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
    except subprocess.CalledProcessError as e:
        print("Error running detection command:")
        print(e.stdout)
        print(e.stderr)

    print("------------------------------------------------------------")


def report_false_positives():
    while True:
        csv_file = input("Enter the CSV file for FP reporting: ").strip()
        if not os.path.isfile(csv_file):
            print(f"File {csv_file} does not exist. Try again.")
            continue

        print("Choose IP type for reporting:")
        print("1 - Destination IP")
        print("2 - Source IP")
        ip_choice = input("Your choice: ").strip()
        if ip_choice not in ['1', '2']:
            print("Invalid choice, try again.")
            continue

        ip_col = "Dst IP" if ip_choice == '1' else "Src IP"

        ip_addresses = input(f"Enter the {ip_col} addresses separated by commas: ").strip()
        ip_list = [ip.strip() for ip in ip_addresses.split(",") if ip.strip()]

        attack_types = ['Port Scan', 'Brute Force', 'Web Attack', 'DoS', 'DDoS', 'Benign']
        print("Choose the NEW attack type to assign to the selected flows:")
        for idx, atk in enumerate(attack_types, 1):
            print(f"{idx} - {atk}")
        try:
            attack_choice = int(input("Your choice: ").strip())
            if attack_choice < 1 or attack_choice > len(attack_types):
                print("Invalid attack choice.")
                continue
            new_attack_type = attack_types[attack_choice - 1]
        except ValueError:
            print("Invalid input for attack type.")
            continue

        df = pd.read_csv(csv_file)
        if ip_col not in df.columns or 'Prediction' not in df.columns:
            print(f"CSV file must contain columns '{ip_col}' and 'Label'.")
            continue

        # Select rows matching the IPs
        selected_flows = df[df[ip_col].isin(ip_list)]

        if selected_flows.empty:
            print("No flows matching the given IP addresses found.")
        else:
            # Update the 'Label' column for these rows to the new attack type
            selected_flows.loc[:, 'Prediction'] = new_attack_type

            fp_file = "Model/FP.csv"
            fp_global_file = "Model/FP-Global.csv"

            # Append updated flows to FP.csv and FP-Global.csv
            selected_flows.to_csv(fp_file, mode='a', index=False, header=not os.path.isfile(fp_file))
            selected_flows.to_csv(fp_global_file, mode='a', index=False, header=not os.path.isfile(fp_global_file))

            print(f"Saved {len(selected_flows)} updated flows with new label '{new_attack_type}' to {fp_file} and {fp_global_file}.")
            print("------------------------------------------------------------")

        cont = input("Report more false positives? (Y/N): ").strip().upper()
        if cont != 'Y':
            break


def run_detection():
    PCAP_DIR = "./Pcap-files"

    while True:
        pcap_name = input("Enter pcap file name to analyze: ").strip()
        pcap_file = os.path.join(PCAP_DIR, pcap_name)

        if not os.path.isfile(pcap_file):
            print(f"File {pcap_file} does not exist. Try again.")
            continue

        print(f"Analyzing {pcap_file}...")
        break

    run_detector(pcap_name)

    report_fp = input("Do you want to report False Positives? (Y/N): ").strip().upper()
    if report_fp == 'Y':
        report_false_positives()

if __name__ == "__main__":
    run_detection()
