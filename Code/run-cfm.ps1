param (
    [Parameter(Mandatory = $true)]
    [string]$PcapFileName
)

# === Java Environment Setup ===
$java = "C:\Program Files\Eclipse Adoptium\jdk-8.0.452.9-hotspot\bin\java.exe"
$nativeLibPath = (Resolve-Path ".\CICFlowMeter-4.0\lib\native").Path
$classpath = ".\CICFlowMeter-4.0\bin;.\CICFlowMeter-4.0\lib\*"

# === Output Directory ===
$outputCsv = ".\CSVs\normal"

# === Handle both relative and absolute PCAP paths ===
if ([System.IO.Path]::IsPathRooted($PcapFileName)) {
    $inputPcap = $PcapFileName
} else {
    $inputPcap = ".\Pcap-files\$PcapFileName"
}

# === Validate PCAP file exists ===
if (-Not (Test-Path $inputPcap)) {
    Write-Error "[ERROR] Input PCAP file not found: $inputPcap"
    exit 1
}

# === Ensure Output Directory Exists ===
if (-Not (Test-Path $outputCsv)) {
    New-Item -ItemType Directory -Path $outputCsv | Out-Null
}

# === Run CICFlowMeter ===
Write-Host "[+] Resolved PCAP path: $inputPcap"
Write-Host "[+] Running CICFlowMeter..."
& $java "-Djava.library.path=$nativeLibPath" -cp "$classpath" cic.cs.unb.ca.ifm.Cmd "$inputPcap" "$outputCsv"

if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Flow generation completed successfully. Output saved to $outputCsv"
} else {
    Write-Error "[ERROR] CICFlowMeter execution failed."
}
