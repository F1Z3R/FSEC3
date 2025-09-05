import subprocess
import os
import sys
import stat

LOG_FILE = "logs/run_log.txt"

def log_and_print(message, log_only=False):
    if not log_only:
        print(message)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")

def make_executable_if_needed(script_path):
    if not os.access(script_path, os.X_OK):
        log_and_print(f"[+] Adding execute permission to {script_path}")
        os.chmod(script_path, os.stat(script_path).st_mode | stat.S_IXUSR)

def run_cfm(pcap_filename, platform_flag):
    if platform_flag == "win":
        ps_command = f'.\\run-cfm.ps1 -PcapFileName \"{pcap_filename}\"'
        full_command = [
            "powershell",
            "-ExecutionPolicy", "Bypass",
            "-Command", ps_command
        ]
        log_and_print(f"[+] Running PowerShell script:\n{ps_command}")

    elif platform_flag == "lin":
        script_path = "./run-cfm.sh"
        make_executable_if_needed(script_path)
        full_command = ["bash", script_path, os.path.basename(pcap_filename)]
        log_and_print(f"[+] Running Bash script:\n{' '.join(full_command)}")

    else:
        log_and_print(f"[!] Invalid platform flag: {platform_flag} (use 'win' or 'lin')")
        sys.exit(1)

    try:
        subprocess.run(full_command, check=True, stdout=sys.stdout, stderr=sys.stderr, text=True)

        completed_summary = subprocess.run(full_command, check=True, capture_output=True, text=True)
        output = completed_summary.stdout + "\n" + completed_summary.stderr

        pkt_stats = ""
        output_folder_line = ""
        for line in output.splitlines():
            if line.startswith("Packet stats:"):
                pkt_stats = line.strip()
            if "Output saved to" in line:
                output_folder_line = line.strip()

        log_and_print("[+] CICFlowMeter summary:")
        if pkt_stats:
            log_and_print(pkt_stats)
        if output_folder_line:
            log_and_print(output_folder_line)
        log_and_print("")

    except subprocess.CalledProcessError as e:
        log_and_print(f"[!] Script failed with error:\n{e.stderr}")
        sys.exit(1)

def run_prediction(pcap_path):
    pcap_name = os.path.basename(pcap_path)
    expected_csv = os.path.join('CSVs', 'normal', f'{pcap_name}_Flow.csv')

    log_and_print(f"[+] Expected CSV path: {expected_csv}")

    if not os.path.isfile(expected_csv):
        log_and_print(f"[!] CSV file not found: {expected_csv}")
        sys.exit(1)

    log_and_print(f"[+] Running prediction on: {expected_csv}")
    try:
        completed = subprocess.run(
            ["python", "Model-Detector.py", expected_csv],
            check=True,
            capture_output=True,
            text=True
        )

        output = completed.stdout + "\n" + completed.stderr
        lines = output.splitlines()

        data_loaded_line = ""
        saved_malicious_line = ""
        saved_benign_line = ""

        # For statistics blocks
        stats_lines = []
        in_stats_block = False

        # For malicious breakdown block
        malicious_breakdown_lines = []
        in_malicious_breakdown = False

        quality_score_line = ""

        for line in lines:
            line_strip = line.strip()

            if line_strip.startswith("Data loaded:"):
                data_loaded_line = line_strip

            elif line_strip.startswith("[OK] Saved ") and "malicious flows to" in line_strip:
                if not saved_malicious_line:
                    saved_malicious_line = line_strip

            elif line_strip.startswith("[OK] Saved ") and "benign flows to" in line_strip:
                if not saved_benign_line:
                    saved_benign_line = line_strip

            elif line_strip == "TRAFFIC SUMMARY":
                # Start stats block
                in_stats_block = True
                stats_lines = [line_strip]

            elif in_stats_block:
                if line_strip == "":
                    # Empty line ends stats block
                    in_stats_block = False
                else:
                    # Skip double bars line inside stats to avoid clutter
                    if set(line_strip) != {'-'}:
                        stats_lines.append(line_strip)

            elif line_strip == "MALICIOUS TRAFFIC BREAKDOWN":
                in_malicious_breakdown = True
                malicious_breakdown_lines = [line_strip]

            elif in_malicious_breakdown:
                if line_strip == "" or "TRAFFIC MALICIOUSNESS RATING" in line_strip:
                    in_malicious_breakdown = False
                else:
                    # Skip double bars or BENIGN line inside breakdown
                    if line_strip.startswith("BENIGN") or set(line_strip) == {'-'}:
                        continue
                    malicious_breakdown_lines.append(line_strip)

            elif line_strip.startswith("→ Overall Traffic Quality Score:"):
                quality_score_line = line_strip

        # Now print clean output
        log_and_print("[+] Prediction summary:")
        if data_loaded_line:
            log_and_print(data_loaded_line)
        if stats_lines:
            log_and_print("*************************************************************")
            for stat_line in stats_lines:
                log_and_print(stat_line)
            log_and_print("*************************************************************")

        if malicious_breakdown_lines:
            for mb_line in malicious_breakdown_lines:
                log_and_print(mb_line)
            log_and_print("*************************************************************")

        if saved_malicious_line:
            log_and_print(saved_malicious_line)
        if saved_benign_line:
            log_and_print(saved_benign_line)

        if quality_score_line:
            log_and_print(quality_score_line)

        log_and_print("")

    except subprocess.CalledProcessError as e:
        log_and_print(f"[!] Prediction script failed:\n{e.stderr}")
        sys.exit(1)

def main():
    os.makedirs("logs", exist_ok=True)
    open(LOG_FILE, "w").close()

    if len(sys.argv) < 3:
        log_and_print("Usage: python Manager.py <pcap_filename> <win|lin>")
        sys.exit(1)

    pcap_input = sys.argv[1].strip('"')
    platform_flag = sys.argv[2].lower()
    pcap_path = os.path.abspath(os.path.join('Pcap-files', pcap_input))

    log_and_print(f"[+] Resolved PCAP path: {pcap_path}")

    if not os.path.isfile(pcap_path):
        log_and_print(f"[!] PCAP file does not exist: {pcap_path}")
        sys.exit(1)

    run_cfm(pcap_path, platform_flag)
    run_prediction(pcap_path)

    log_and_print("[+] Process completed. Check logs/run_log.txt for details.")

if __name__ == "__main__":
    main()
