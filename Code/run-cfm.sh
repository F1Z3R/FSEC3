#!/bin/bash

# Check if PCAP filename argument is provided
if [ -z "$1" ]; then
  echo "[ERROR] Please provide the PCAP filename as the first argument."
  exit 1
fi

PcapFileName="$1"

# Paths - replace these if your directory structure differs
JAVA="/usr/local/java/jre1.8.0_461/bin/java"
BASE_DIR=$(pwd)  # Current working directory where you run the script
NATIVE_LIB_PATH="$BASE_DIR/CICFlowMeter-4.0/lib/native"
CLASSPATH="$BASE_DIR/CICFlowMeter-4.0/bin:$BASE_DIR/CICFlowMeter-4.0/lib/*"
OUTPUT_CSV="$BASE_DIR/CSVs/normal"

# Handle absolute or relative PCAP path
if [[ "$PcapFileName" = /* ]]; then
  INPUT_PCAP="$PcapFileName"
else
  INPUT_PCAP="$BASE_DIR/Pcap-files/$PcapFileName"
fi

# Validate input PCAP file exists
if [ ! -f "$INPUT_PCAP" ]; then
  echo "[ERROR] Input PCAP file not found: $INPUT_PCAP"
  exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_CSV"

echo "[+] Resolved PCAP path: $INPUT_PCAP"
echo "[+] Running CICFlowMeter..."

# Run CICFlowMeter using Java with native lib path and classpath set
"$JAVA" -Djava.library.path="$NATIVE_LIB_PATH" -cp "$CLASSPATH" cic.cs.unb.ca.ifm.Cmd "$INPUT_PCAP" "$OUTPUT_CSV"
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo "[OK] Flow generation completed successfully. Output saved to $OUTPUT_CSV"
else
  echo "[ERROR] CICFlowMeter execution failed."
fi
