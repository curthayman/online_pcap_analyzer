# Advanced PCAP Analyzer

A modular Python script for advanced PCAP analysis, including:

- Protocol and conversation summaries
- VPN and broadcast detection
- Credential extraction
- DNS and ARP analysis
- GeoIP lookups
- Visualization
- File extraction
- Threat feed integration

---

## Requirements

- Python 3.7+
- See `requirements.txt` for dependencies

- If you run into errors with weasyprint (especially on macOS or Linux), you may need to install system libraries. For example, on Ubuntu:
- sudo apt-get install libpango-1.0-0 libcairo2 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info

---

## Setup

1. **Install dependencies:**

   pip install -r requirements.txt

2. (Optional) For GeoIP lookups:
   Register for a free account and download the GeoLite2 City database.
   Place GeoLite2-City.mmdb in the script directory.

3. Usage:
   python pcap_analyzer.py [options]

4. Options:
- --geoip : Enable GeoIP lookups (requires GeoLite2-City.mmdb and geoip2)
- --visualize : Show protocol distribution pie chart (requires matplotlib)
- --extract-files : Extract files from HTTP traffic
- --threat-feed <file> : Path to file with known bad IPs (one per line)
- --no-dns : Disable DNS query/response analysis
- --no-arp : Disable ARP spoofing detection
- --no-tls : Disable TLS/SSL handshake detection
- --no-creds : Disable credential extraction
- --no-broadcast : Disable broadcast traffic analysis

5. Example
   python pcap_analyzer.py --geoip --visualize --extract-files

6. Feature Details
   GeoIP Lookups:

   When --geoip is enabled and the GeoLite2 database is present, the script will display city and country information for public IPs in the summary output.

   Visualization:

   Use --visualize to display a protocol distribution pie chart (requires matplotlib).

   File Extraction:

   Use --extract-files to extract files from HTTP traffic (saved in the extracted_files/ directory).

   Threat Feed:

   Use --threat-feed <file> to highlight traffic involving known bad IPs (one IP per line in the file).

   Feature Toggles:

   Use the --no-* flags to disable specific analyses for faster or more focused runs.

  * Credits
     scapy>=2.4.0
     requests
     prompt_toolkit
     tqdm
     jinja2
     weasyprint
     geoip2
     matplotlib
     curtthecoder
7. Notes
    Private IP addresses (e.g., 192.168.x.x) will not have GeoIP data.
    For best results, use with PCAPs containing public internet traffic.
    For any issues or feature requests, please open an issue on GitHub.

    If you don’t need GeoIP or PDF/HTML export, you can remove geoip2 and/or weasyprint.
    If you’re on macOS or Windows, you may need additional system packages for weasyprint and matplotlib (e.g., Cairo, Pango, GDK-Pixbuf for WeasyPrint).
    All packages are compatible with Python 3.10/3.11 (recommended for Scapy).
