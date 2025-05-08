import streamlit as st
import tempfile
import os
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Ether, Raw, DNS, DNSQR, ARP
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp
from collections import Counter, defaultdict
import socket
import re
import base64

st.set_page_config(page_title="PCAP Analyzer Dashboard", layout="wide")

st.title("📊 PCAP Analyzer Dashboard")

st.markdown("""
Upload a PCAP file to analyze network traffic, detect access points, suspicious file transfers, credentials, and more.
""")

uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "cap"])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    packets = rdpcap(tmp_path)

    ip_counter = Counter()
    proto_counter = Counter()
    src_dst_counter = Counter()
    broadcast_counter = Counter()
    credentials = []
    dns_queries = Counter()
    dns_responses = Counter()
    arp_table = defaultdict(set)
    suspicious_transfers = []
    access_points = {}

    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".js", ".scr", ".bat", ".vbs", ".dll", ".ps1", ".jar", ".zip", ".rar", ".7z", ".msi", ".apk", ".sh", ".py", ".pl", ".php", ".asp", ".aspx", ".jsp", ".bin", ".dat", ".cmd", ".com", ".cpl", ".gadget", ".wsf", ".pif", ".vb", ".vbe", ".hta", ".msc", ".msp", ".mst", ".scf", ".lnk", ".inf", ".reg", ".sys", ".drv", ".ocx", ".ax", ".mod", ".mde", ".ade", ".adp", ".bas", ".chm", ".crt", ".csh", ".fxp", ".hlp", ".ins", ".isp", ".jse", ".ksh", ".mad", ".maf", ".mag", ".mam", ".maq", ".mar", ".mas", ".mat", ".mau", ".mav", ".maw", ".mda", ".mdb", ".mdt", ".mdw", ".mdz", ".ops", ".pcd", ".prg", ".pst", ".sct", ".shb", ".shs", ".url", ".wsc", ".xnk"
    }

    def resolve_hostname(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"

    def extract_credentials(pkt):
        if not (TCP in pkt and Raw in pkt):
            return None
        payload = pkt[Raw].load
        try:
            payload_str = payload.decode(errors='ignore')
        except Exception:
            return None

        dst_ip = pkt[IP].dst if IP in pkt else None

        m = re.search(r'Authorization: Basic ([A-Za-z0-9+/=]+)', payload_str)
        if m:
            host = None
            host_match = re.search(r'Host: ([^\r\n]+)', payload_str)
            if host_match:
                host = host_match.group(1)
            try:
                decoded = base64.b64decode(m.group(1)).decode(errors='ignore')
                return {
                    "type": "HTTP Basic Auth",
                    "username_password": decoded,
                    "host": host,
                    "dst_ip": dst_ip
                }
            except Exception:
                pass

        if payload_str.startswith("POST"):
            host = None
            host_match = re.search(r'Host: ([^\r\n]+)', payload_str)
            if host_match:
                host = host_match.group(1)
            post_body = payload_str.split('\r\n\r\n', 1)
            if len(post_body) == 2:
                params = post_body[1]
                user = re.search(r'(user(name)?|login)=([^&\s]+)', params, re.IGNORECASE)
                pwd = re.search(r'(pass(word)?|pwd)=([^&\s]+)', params, re.IGNORECASE)
                if user and pwd:
                    return {
                        "type": "HTTP POST",
                        "username_password": f"username={user.group(3)} password={pwd.group(3)}",
                        "host": host,
                        "dst_ip": dst_ip
                    }

        for proto in ['USER', 'PASS', 'LOGIN', 'Password:']:
            if proto in payload_str:
                user = re.search(r'USER\s+([^\r\n]+)', payload_str)
                pwd = re.search(r'PASS\s+([^\r\n]+)', payload_str)
                if user and pwd:
                    return {
                        "type": "FTP/POP3/IMAP",
                        "username_password": f"username={user.group(1)} password={pwd.group(1)}",
                        "host": None,
                        "dst_ip": dst_ip
                    }
                login = re.search(r'LOGIN\s+([^\r\n]+)', payload_str)
                password = re.search(r'Password:\s*([^\r\n]+)', payload_str)
                if login and password:
                    return {
                        "type": "Telnet/Other",
                        "username_password": f"username={login.group(1)} password={password.group(1)}",
                        "host": None,
                        "dst_ip": dst_ip
                    }
        return None

    def detect_suspicious_file_transfer(pkt):
        # HTTP
        if TCP in pkt and Raw in pkt:
            try:
                payload = pkt[Raw].load.decode(errors='ignore')
            except Exception:
                return
            # HTTP GET/POST/Response
            if payload.startswith("GET") or payload.startswith("POST"):
                m = re.search(r"GET\s+([^\s]+)", payload)
                if m:
                    uri = m.group(1)
                    ext = os.path.splitext(uri)[1].lower()
                    if ext in SUSPICIOUS_EXTENSIONS:
                        suspicious_transfers.append({
                            "protocol": "HTTP",
                            "src": pkt[IP].src if IP in pkt else "",
                            "dst": pkt[IP].dst if IP in pkt else "",
                            "filename": uri,
                            "extension": ext
                        })
            elif payload.startswith("HTTP/1.1 200 OK") or payload.startswith("HTTP/1.0 200 OK"):
                m = re.search(r"Content-Disposition:.*filename=\"?([^\"]+)\"?", payload, re.IGNORECASE)
                if m:
                    filename = m.group(1)
                    ext = os.path.splitext(filename)[1].lower()
                    if ext in SUSPICIOUS_EXTENSIONS:
                        suspicious_transfers.append({
                            "protocol": "HTTP",
                            "src": pkt[IP].src if IP in pkt else "",
                            "dst": pkt[IP].dst if IP in pkt else "",
                            "filename": filename,
                            "extension": ext
                        })
        # FTP (look for STOR, RETR, or file names in payload)
        if TCP in pkt and Raw in pkt:
            try:
                payload = pkt[Raw].load.decode(errors='ignore')
            except Exception:
                return
            m = re.search(r"(STOR|RETR)\s+([^\r\n]+)", payload)
            if m:
                filename = m.group(2)
                ext = os.path.splitext(filename)[1].lower()
                if ext in SUSPICIOUS_EXTENSIONS:
                    suspicious_transfers.append({
                        "protocol": "FTP",
                        "src": pkt[IP].src if IP in pkt else "",
                        "dst": pkt[IP].dst if IP in pkt else "",
                        "filename": filename,
                        "extension": ext
                    })

    def detect_access_point(pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt[Dot11].addr3
            ssid = pkt[Dot11].info.decode(errors="ignore") if hasattr(pkt[Dot11], "info") else "<hidden>"
            channel = None
            crypto = set()
            elt = None
            if pkt.haslayer(Dot11Beacon):
                elt = pkt[Dot11Beacon].payload
            elif pkt.haslayer(Dot11ProbeResp):
                elt = pkt[Dot11ProbeResp].payload
            while elt and hasattr(elt, "ID"):
                if elt.ID == 3:  # DS Parameter Set: Current Channel
                    channel = elt.info[0]
                if elt.ID == 48:
                    crypto.add("WPA2")
                if elt.ID == 221 and elt.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    crypto.add("WPA")
                elt = elt.payload if hasattr(elt, "payload") else None
            if pkt[Dot11].cap & 0x10:
                crypto.add("WEP")
            if not crypto:
                crypto.add("OPEN")
            access_points[bssid] = {
                "ssid": ssid,
                "channel": channel,
                "crypto": "/".join(crypto)
            }

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            ip_counter.update([src, dst])
            src_dst_counter.update([(src, dst)])
            if TCP in pkt:
                proto_counter.update(['TCP'])
            elif UDP in pkt:
                proto_counter.update(['UDP'])
            elif ICMP in pkt:
                proto_counter.update(['ICMP'])
            if not (dst == "255.255.255.255" or dst.startswith("224.")):
                pass
            else:
                broadcast_counter.update([src])
        elif Ether in pkt:
            if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
                broadcast_counter.update([pkt[Ether].src])
        elif ARP in pkt:
            arp_table[pkt[ARP].psrc].add(pkt[ARP].hwsrc)
        if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
            dns_queries.update([pkt[DNSQR].qname.decode(errors='ignore')])
        if DNS in pkt and pkt[DNS].qr == 1:
            for i in range(pkt[DNS].ancount):
                try:
                    dns_responses.update([pkt[DNS].an[i].rdata])
                except Exception:
                    pass
        cred = extract_credentials(pkt)
        if cred:
            credentials.append(cred)
        detect_suspicious_file_transfer(pkt)
        detect_access_point(pkt)

    arp_spoofed = {ip: macs for ip, macs in arp_table.items() if len(macs) > 1}

    st.header("Summary")
    st.write(f"**Total packets:** {len(packets)}")
    st.write(f"**Unique IPs:** {len(ip_counter)}")

    st.subheader("Top IPs")
    st.dataframe(
        [{"IP": ip, "Hostname": resolve_hostname(ip), "Packets": count}
         for ip, count in ip_counter.most_common(10)]
    )

    st.subheader("Protocol Distribution")
    st.bar_chart(proto_counter)

    st.subheader("Top Conversations")
    st.dataframe(
        [{"Source": src, "Destination": dst, "Packets": count}
         for (src, dst), count in src_dst_counter.most_common(10)]
    )

    st.subheader("Broadcast Traffic")
    if broadcast_counter:
        st.dataframe(
            [{"Source": src, "Packets": count}
             for src, count in broadcast_counter.most_common(10)]
        )
    else:
        st.write("No broadcast traffic detected.")

    st.subheader("Access Points (802.11 Beacons/Probe Responses)")
    if access_points:
        st.dataframe(
            [{"BSSID": bssid, "SSID": ap["ssid"], "Channel": ap["channel"], "Crypto": ap["crypto"]}
             for bssid, ap in access_points.items()]
        )
    else:
        st.write("No access points detected (no 802.11 beacons/probe responses found).")

    st.subheader("Suspicious File Transfers")
    if suspicious_transfers:
        st.dataframe(suspicious_transfers)
    else:
        st.write("No suspicious file transfers detected.")

    st.subheader("Credential Extraction")
    if credentials:
        st.dataframe(credentials)
    else:
        st.write("No credentials found in cleartext traffic.")

    st.subheader("DNS Queries (Top 10)")
    st.dataframe(
        [{"Query": q, "Count": count} for q, count in dns_queries.most_common(10)]
    )

    st.subheader("DNS Responses (Top 10)")
    st.dataframe(
        [{"Response": str(resp), "Count": count} for resp, count in dns_responses.most_common(10)]
    )

    st.subheader("ARP Spoofing Detection")
    if arp_spoofed:
        st.write("Potential ARP spoofing detected! Multiple MACs for same IP:")
        for ip, macs in arp_spoofed.items():
            st.write(f"- {ip}: {', '.join(macs)}")
    else:
        st.write("No ARP spoofing detected.")

    os.remove(tmp_path)
else:
    st.info("Please upload a PCAP file to begin analysis.")
