import streamlit as st
import tempfile
import os
from collections import Counter, defaultdict
import socket
import re
import base64

st.set_page_config(page_title="PCAP/PCAPNG Analyzer Dashboard", layout="wide")
st.title("📊 PCAP/PCAPNG Analyzer Dashboard")

st.markdown("""
Upload a `.pcap` or `.pcapng` file to analyze network traffic, detect access points, suspicious file transfers, credentials, and more.
""")

uploaded_file = st.file_uploader("Upload a PCAP or PCAPNG file", type=["pcap", "pcapng", "cap"])

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".js", ".scr", ".bat", ".vbs", ".dll", ".ps1", ".jar", ".zip", ".rar", ".7z", ".msi", ".apk", ".sh", ".py", ".pl", ".php", ".asp", ".aspx", ".jsp", ".bin", ".dat", ".cmd", ".com", ".cpl", ".gadget", ".wsf", ".pif", ".vb", ".vbe", ".hta", ".msc", ".msp", ".mst", ".scf", ".lnk", ".inf", ".reg", ".sys", ".drv", ".ocx", ".ax", ".mod", ".mde", ".ade", ".adp", ".bas", ".chm", ".crt", ".csh", ".fxp", ".hlp", ".ins", ".isp", ".jse", ".ksh", ".mad", ".maf", ".mag", ".mam", ".maq", ".mar", ".mas", ".mat", ".mau", ".mav", ".maw", ".mda", ".mdb", ".mdt", ".mdw", ".mdz", ".ops", ".pcd", ".prg", ".pst", ".sct", ".shb", ".shs", ".url", ".wsc", ".xnk"
}

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

def extract_credentials_scapy(pkt):
    from scapy.all import IP, TCP, Raw
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

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    file_ext = os.path.splitext(uploaded_file.name)[1].lower()

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

    if file_ext == ".pcap":
        # Use Scapy for .pcap (fast, full credential extraction)
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Ether, Raw, DNS, DNSQR, ARP
        from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp

        st.info("Parsing with Scapy (fast, full credential extraction)...")
        packets = rdpcap(tmp_path)

        def detect_suspicious_file_transfer(pkt):
            if TCP in pkt and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode(errors='ignore')
                except Exception:
                    return
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
                if dst == "255.255.255.255" or dst.startswith("224."):
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
            cred = extract_credentials_scapy(pkt)
            if cred:
                credentials.append(cred)
            detect_suspicious_file_transfer(pkt)
            detect_access_point(pkt)

    else:
        # Use pyshark for .pcapng and other formats
        import pyshark
        st.info("Parsing with Pyshark (slower, limited credential extraction for some protocols)...")
        try:
            packets = list(pyshark.FileCapture(tmp_path, keep_packets=False))
        except Exception as e:
            st.error(f"Could not parse file: {e}")
            os.remove(tmp_path)
            st.stop()

        def get_attr(obj, attr):
            try:
                return getattr(obj, attr)
            except Exception:
                return None

        for pkt in packets:
            try:
                if hasattr(pkt, 'ip'):
                    src = get_attr(pkt.ip, 'src')
                    dst = get_attr(pkt.ip, 'dst')
                    if src and dst:
                        ip_counter.update([src, dst])
                        src_dst_counter.update([(src, dst)])
            except Exception:
                pass

            try:
                if hasattr(pkt, 'transport_layer'):
                    proto_counter.update([pkt.transport_layer])
            except Exception:
                pass

            try:
                if hasattr(pkt, 'eth') and hasattr(pkt.eth, 'dst'):
                    if pkt.eth.dst == "ff:ff:ff:ff:ff:ff":
                        broadcast_counter.update([pkt.eth.src])
            except Exception:
                pass

            try:
                if hasattr(pkt, 'dns'):
                    if hasattr(pkt.dns, 'qry_name'):
                        dns_queries.update([pkt.dns.qry_name])
                    if hasattr(pkt.dns, 'a'):
                        dns_responses.update([pkt.dns.a])
            except Exception:
                pass

            try:
                if hasattr(pkt, 'arp'):
                    arp_table[get_attr(pkt.arp, 'src_proto_ipv4')].add(get_attr(pkt.arp, 'src_hw_mac'))
            except Exception:
                pass

            try:
                if hasattr(pkt, 'http'):
                    if hasattr(pkt.http, 'authorization'):
                        auth = pkt.http.authorization
                        if auth.lower().startswith("basic "):
                            b64 = auth[6:]
                            try:
                                decoded = base64.b64decode(b64).decode(errors='ignore')
                            except Exception:
                                decoded = "<decode error>"
                            credentials.append({
                                "type": "HTTP Basic Auth",
                                "username_password": decoded,
                                "host": pkt.http.host if hasattr(pkt.http, 'host') else "",
                                "dst_ip": pkt.ip.dst if hasattr(pkt, 'ip') else ""
                            })
                    if hasattr(pkt.http, 'request_uri'):
                        uri = pkt.http.request_uri
                        ext = os.path.splitext(uri)[1].lower()
                        if ext in SUSPICIOUS_EXTENSIONS:
                            suspicious_transfers.append({
                                "protocol": "HTTP",
                                "src": pkt.ip.src if hasattr(pkt, 'ip') else "",
                                "dst": pkt.ip.dst if hasattr(pkt, 'ip') else "",
                                "filename": uri,
                                "extension": ext
                            })
                    if hasattr(pkt.http, 'content_disposition'):
                        import re
                        m = re.search(r'filename="?([^";]+)"?', pkt.http.content_disposition)
                        if m:
                            filename = m.group(1)
                            ext = os.path.splitext(filename)[1].lower()
                            if ext in SUSPICIOUS_EXTENSIONS:
                                suspicious_transfers.append({
                                    "protocol": "HTTP",
                                    "src": pkt.ip.src if hasattr(pkt, 'ip') else "",
                                    "dst": pkt.ip.dst if hasattr(pkt, 'ip') else "",
                                    "filename": filename,
                                    "extension": ext
                                })
                if hasattr(pkt, 'ftp'):
                    if hasattr(pkt.ftp, 'request_arg'):
                        filename = pkt.ftp.request_arg
                        ext = os.path.splitext(filename)[1].lower()
                        if ext in SUSPICIOUS_EXTENSIONS:
                            suspicious_transfers.append({
                                "protocol": "FTP",
                                "src": pkt.ip.src if hasattr(pkt, 'ip') else "",
                                "dst": pkt.ip.dst if hasattr(pkt, 'ip') else "",
                                "filename": filename,
                                "extension": ext
                            })
                    if hasattr(pkt.ftp, 'request_command'):
                        cmd = pkt.ftp.request_command
                        if cmd in ["USER", "PASS"]:
                            credentials.append({
                                "type": "FTP",
                                "username_password": f"{cmd} {pkt.ftp.request_arg}",
                                "host": "",
                                "dst_ip": pkt.ip.dst if hasattr(pkt, 'ip') else ""
                            })
                if hasattr(pkt, 'wlan'):
                    if hasattr(pkt.wlan, 'bssid') and hasattr(pkt.wlan, 'ssid'):
                        bssid = pkt.wlan.bssid
                        ssid = pkt.wlan.ssid
                        channel = getattr(pkt.wlan_radio, 'channel', None) if hasattr(pkt, 'wlan_radio') else None
                        crypto = "WPA/WPA2" if hasattr(pkt.wlan, 'rsn') else "OPEN"
                        access_points[bssid] = {
                            "ssid": ssid,
                            "channel": channel,
                            "crypto": crypto
                        }
            except Exception:
                pass

    arp_spoofed = {ip: macs for ip, macs in arp_table.items() if len(macs) > 1}

    st.header("Summary")
    st.write(f"**Total packets:** {len(ip_counter)}")
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
        if file_ext != ".pcap":
            st.info("Note: For .pcapng files, only credentials in parsed protocol fields (e.g., HTTP Basic Auth, FTP USER/PASS) are shown. Full POST body and Telnet credential extraction is only available for .pcap files.")
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
    st.info("Please upload a PCAP or PCAPNG file to begin analysis.")