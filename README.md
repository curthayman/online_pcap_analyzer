# 📊 PCAP/PCAPNG Analyzer Dashboard
A powerful, interactive Streamlit dashboard for analyzing .pcap and .pcapng network capture files. Instantly visualize network traffic, detect suspicious file transfers, extract credentials, identify access points, and more—all from your browser.

## Features
- Upload & Analyze: Supports .pcap, .pcapng, and .cap files.
- Traffic Overview: See top IPs, protocol distribution, and top conversations.
- Suspicious File Detection: Flags transfers of potentially malicious file types (e.g., .exe, .js, .bat, etc.).
- Credential Extraction: Extracts HTTP Basic Auth, FTP, Telnet, and POST credentials (where possible).
- Access Point Discovery: Detects 802.11 beacons and probe responses (SSID, channel, crypto).
- DNS Analysis: Top DNS queries and responses.
- ARP Spoofing Detection: Highlights multiple MACs for the same IP.
- Broadcast Traffic: Identifies broadcast-heavy sources.
- User-Friendly: All results are presented in interactive tables and charts.
  
## Demo
Coming soon!

## Installation
1. Clone the repository
```
git clone https://github.com/your-username/pcap-analyzer-dashboard.git
```
```
cd pcap-analyzer-dashboard
```
## 2. Install dependencies
Python 3.8+ required
```
pip install -r requirements.txt
```
## Dependencies:

- streamlit
- scapy
- pyshark
- (and their dependencies)
## 3. Run the app

```
streamlit run pcap_dashboard.py
```
## Usage
Open your browser to the Streamlit URL (usually http://localhost:8501).
Upload a .pcap or .pcapng file.
Explore the interactive dashboard!


## How It Works
- .pcap files: Parsed with Scapy for fast, deep analysis (including full credential extraction and 802.11 support).
- .pcapng files: Parsed with Pyshark (slower, but supports more modern capture formats).
- Suspicious Extensions: Transfers of files with risky extensions (e.g., .exe, .js, .bat, etc.) are flagged.
- Credential Extraction: Attempts to extract cleartext credentials from HTTP, FTP, Telnet, and POST bodies.
- Access Points: Detects Wi-Fi beacons and probe responses, showing SSID, channel, and encryption.
- ARP Spoofing: Flags IPs with multiple MAC addresses.


## Security & Privacy
- All analysis is local: No data is sent to any server.
- Temporary files: Uploaded files are stored temporarily and deleted after analysis.


## Limitations
- Encrypted traffic: Cannot extract credentials from encrypted protocols (HTTPS, SSH, etc.).
- .pcapng: Some credential extraction is limited due to Pyshark parsing.
- Large files: Performance may degrade with very large capture files.


## Contributing
Pull requests and issues are welcome!

Please open an issue for bugs, feature requests, or questions.

## License
MIT License

## Credits
Built with Streamlit, Scapy, and Pyshark.
Inspired by Wireshark and other network analysis tools.


## Author
Curt Hayman


## Disclaimer
For educational and authorized security analysis only.

Do not use on networks or files you do not have permission to analyze.

Happy analyzing! 🚀
