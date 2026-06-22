# PCAP Analyzer

A browser-based network traffic analysis tool for analyzing PCAP and PCAPNG files. Features VPN detection, protocol decoding, network topology visualization, HTTP/DNS analysis, file extraction, and credential detection — all running locally with no data leaving your machine.

## Features

### Visualizations & Analysis
- 📊 **Executive Summary** - At-a-glance overview with color-coded security status and VPN detection banner
- 🥧 **Protocol Distribution Pie Chart** - Visual breakdown of network protocols with percentages
- 📊 **Top Talkers Bar Chart** - Identify the most active hosts by packet count
- 🕸️ **Network Topology Graph** - Interactive visualization of connections between nodes
- 📡 **WiFi Network Detection** - Detect and analyze wireless networks (SSID, BSSID, encryption, clients)

### VPN Detection
- 🔒 **Automatic VPN Detection** - Identifies when a capture was recorded behind a VPN
- Detects explicit VPN protocols: ESP (IPsec), GRE, PPTP, IKE, OpenVPN, WireGuard, L2TP
- Detects **QUIC-tunneled VPNs** — VPNs that disguise traffic over UDP/443 (VPN-over-HTTPS obfuscation)
- Shows confidence level, tunnel endpoint, and specific indicators
- Warns that payload content will be encrypted and unreadable when VPN is active

### Protocol Support & Deep Inspection
- 🔍 **Protocol Analysis** - HTTP, DNS, TCP, UDP, IPv4/IPv6, FTP, Telnet, ICMP, VPN (PPTP, OpenVPN, WireGuard, IPsec)
- 🌐 **HTTP Analysis** - Full request/response inspection with headers and status codes
- 🔎 **DNS Query Analysis** - Track domain lookups and responses
- 📁 **File Extraction** - Carve and download files from network traffic
- 🔐 **Credential Detection** - Identify plaintext credentials (HTTP Basic Auth, FTP, Telnet)
- 🔬 **Packet Detail Viewer** - Click any packet for a full breakdown
- 🌊 **TCP Stream Reconstruction** - Follow and read TCP streams between hosts
- 🔎 **Packet Filter** - Wireshark-style filter bar to search packets by protocol, IP, port, or keyword

### User Experience
- 📈 **Real-time Progress** - Live progress updates with SSE during PCAP analysis
- 🎨 **Beautiful UI** - Professional design with dark/light mode support
- 📊 **Rich Statistics Cards** - Total packets, data volume, duration, and more
- 💾 **Large File Support** - Handle PCAP files up to 500MB

## Requirements

- **Node.js** 18 or higher (tested on Node.js 20)
- **macOS** or Linux
- **RAM**: 4GB minimum (8GB recommended for large PCAP files)

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/curthayman/online_pcap_analyzer.git
cd online_pcap_analyzer
```

### 2. Install Dependencies

```bash
npm install
```

This will install all required packages including React, Express, and the PCAP parsing library.

### 3. Run the Application

**Development Mode** (with hot reload):
```bash
npm run dev
```

The application will start on **http://localhost:3000**

**Production Build**:
```bash
npm run build
npm start
```

## Usage

1. **Open your browser** and navigate to `http://localhost:3000`

2. **Upload a PCAP file** by:
   - Dragging and dropping a `.pcap`, `.pcapng`, or `.cap` file onto the upload zone
   - Or clicking to browse and select a file

3. **Watch real-time progress** as the file is analyzed through these phases:
   - Uploading (5%)
   - Parsing (10%)
   - Analyzing (20-70%)
   - Finalizing (75-95%)
   - Completed (100%)

4. **Explore the analysis** in the dashboard:
   - **Executive Summary**: High-level overview with color-coded security status
   - **Overview Tab**:
     - Network topology graph
     - Protocol distribution pie chart with percentages
     - Top talkers bar chart showing most active hosts
   - **HTTP Tab**: HTTP requests/responses with headers and status codes
   - **DNS Tab**: DNS queries and responses
   - **WiFi Tab** (if applicable): Detected wireless networks with encryption info
   - **Files Tab**: Extracted files available for download
   - **Credentials Tab**: Detected plaintext credentials
   - **Packets Tab**: Raw packet details

## File Size Limits

- Maximum file size: **500MB**
- Supported formats: `.pcap`, `.pcapng`, `.cap`

For optimal performance with very large files (>100MB), the analyzer automatically limits packet processing while maintaining statistical accuracy.

## Architecture

### Frontend
- **React 18** with TypeScript
- **Vite** for build tooling and HMR
- **Wouter** for routing
- **TanStack Query** for data fetching
- **Tailwind CSS** + **shadcn/ui** for styling
- **Canvas API** for network graph visualization

### Backend
- **Express.js** server
- **pcap-parser** for PCAP file parsing
- **Server-Sent Events (SSE)** for real-time progress
- In-memory storage (no database required)

### Key Files
- `client/src/pages/home.tsx` - Landing page with file upload
- `client/src/pages/analysis.tsx` - Analysis dashboard
- `server/pcap-analyzer.ts` - PCAP parsing and analysis logic
- `server/routes.ts` - API endpoints
- `shared/schema.ts` - TypeScript types and Zod schemas

## Development

### Project Structure
```
.
├── client/              # Frontend React application
│   └── src/
│       ├── components/  # Reusable UI components
│       ├── pages/       # Page components
│       ├── hooks/       # Custom React hooks
│       └── lib/         # Utilities
├── server/              # Backend Express server
│   ├── routes.ts        # API routes
│   ├── pcap-analyzer.ts # PCAP parsing logic
│   └── storage.ts       # Data storage
├── shared/              # Shared types and schemas
└── public/              # Static assets
```

### Available Scripts

- `npm run dev` - Start development server (frontend + backend)
- `npm run build` - Build for production
- `npm start` - Run production build
- `npm run check` - TypeScript type checking

## Troubleshooting

**Port 3000 already in use:**
```bash
# Find and kill the process using port 3000
lsof -ti:3000 | xargs kill -9
```

**Out of memory errors:**
- Reduce PCAP file size
- Close other applications
- Increase Node.js heap size: `NODE_OPTIONS="--max-old-space-size=4096" npm run dev`

**Module not found errors:**
```bash
# Clean install
rm -rf node_modules package-lock.json
npm install
```

## Security Notes

- This application is designed for **local use only**
- Do not expose to the internet without proper security measures
- PCAP files may contain sensitive network data - handle with care
- Extracted credentials are displayed in plaintext for analysis purposes

## License

MIT License - See LICENSE file for details

## Support

For issues or questions, please open an issue in the repository.
