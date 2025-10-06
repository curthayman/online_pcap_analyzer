# PCAP Analyzer

## Overview

PCAP Analyzer is a browser-based network traffic analysis tool that allows users to upload and analyze PCAP files. The application parses network packet captures to extract valuable information including network topology, HTTP transactions, DNS queries, extracted files, and credentials. It provides interactive visualizations and detailed tables for security professionals and network analysts to examine network traffic patterns.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture

**Framework & Build System**
- React 18 with TypeScript for type-safe component development
- Vite as the build tool and development server with HMR (Hot Module Replacement)
- Wouter for lightweight client-side routing
- TanStack Query (React Query) for server state management and caching

**UI Component System**
- Radix UI primitives for accessible, unstyled component foundation
- shadcn/ui component library built on Radix UI with "new-york" style variant
- Tailwind CSS for utility-first styling with custom design tokens
- Custom design system inspired by Material Design and Carbon Design System for professional data presentation
- Dark mode support with theme toggling capability

**State Management Approach**
- Server state managed through React Query with infinite stale time (client-side caching)
- Real-time progress updates via Server-Sent Events (SSE) with custom `useProgress` hook
- Form state handled by React Hook Form with Zod validation
- No global state management library - leveraging React Query and component composition

**Key Design Decisions**
- Protocol-specific color coding for visual distinction (HTTP: purple, DNS: teal, WiFi: orange)
- Professional color palette optimized for both light and dark modes
- Information density prioritized for technical users
- Canvas-based network graph visualization for performance with large datasets

### Backend Architecture

**Server Framework**
- Express.js as the HTTP server framework
- Node.js with ES modules (type: "module" in package.json)
- TypeScript for type safety across the stack
- Development server uses tsx for TypeScript execution

**Request Processing Flow**
1. File upload via Multer middleware with validation (25MB limit, .pcap/.pcapng/.cap extensions only)
2. Files stored temporarily in OS temp directory
3. PCAP parsing using pcap-parser library with stream processing
4. Real-time progress updates broadcast via SSE
5. Analysis results stored in memory and returned to client

**Data Processing**
- PCAP file parsing with dual parser support:
  - `pcap-parser` for classic PCAP format (magic number 0xa1b2c3d4)
  - `pcap-ng-parser` for PCAPNG format (magic number 0x0a0d0d0a)
- Automatic format detection by reading file magic number
- Network topology extracted by analyzing source/destination IPs and MAC addresses
- Protocol detection and classification from packet headers:
  - HTTP, DNS, FTP, Telnet (standard protocols)
  - **STUN** - WebRTC NAT traversal (reliable indicator of Slack, Zoom, WebRTC video calls)
  - **VPN Protocols** - ESP, IKE, OpenVPN, WireGuard, L2TP, PPTP, GRE (IPsec and VPN traffic detection)
  - **WiFi (802.11)** - Wireless network frame analysis with Radiotap header support
- Link layer type detection for different capture formats:
  - Ethernet (linkLayerType 1) - standard wired networks
  - IEEE 802.11 with Radiotap (linkLayerType 127) - WiFi with signal strength and channel info
  - IEEE 802.11 raw (linkLayerType 105) - basic WiFi frame parsing
- WiFi frame parsing capabilities:
  - SSID extraction from beacon and probe frames
  - BSSID (access point MAC address) identification
  - Signal strength (dBm) from Radiotap headers
  - Channel and data rate detection
  - Encryption detection (WPA/WPA2/Open networks)
  - Client device tracking by MAC address
  - Frame type classification (Management, Control, Data)
- HTTP transaction reconstruction from TCP streams
- DNS query extraction and response mapping
- Credential detection through pattern matching in cleartext protocols
- File extraction from HTTP responses with base64 encoding for transport
- WebRTC/video call detection via STUN protocol analysis

**API Design**
- RESTful endpoints for file upload and analysis retrieval
- Server-Sent Events endpoint (`/api/progress/:id`) for real-time progress streaming
- JSON response format with structured error handling
- Request logging middleware for debugging (logs truncated to 80 characters)

### Data Storage

**Current Implementation**
- In-memory storage using Map data structure (`MemStorage` class)
- No database persistence - data lost on server restart
- Analysis results indexed by UUID for quick retrieval

**Database Schema (Drizzle ORM)**
- Drizzle ORM configured with PostgreSQL dialect
- Schema defined in `shared/schema.ts` using Zod for runtime validation
- Database migrations stored in `./migrations` directory
- Environment variable `DATABASE_URL` required for database connection
- Note: Database is currently configured but not actively used (in-memory storage active)

**Schema Models**
- `PcapAnalysis`: Metadata about uploaded PCAP files and analysis status
- `NetworkNode`: IP/MAC addresses with node classification (router, server, client)
- `NetworkConnection`: Source-destination pairs with protocol and traffic volume
- `HttpTransaction`: Request/response pairs with headers and status codes
- `DnsQuery`: DNS lookups with query type and responses
- `ExtractedFile`: Files extracted from traffic with base64-encoded data
- `Credential`: Username/password pairs found in cleartext protocols
- `Packet`: Individual packet details with timestamp and protocol info
- `WiFiFrame`: 802.11 wireless frame details with SSID, BSSID, signal strength, and channel info
- `WiFiNetwork`: Aggregated WiFi network information with beacon counts, encryption, and client tracking

### External Dependencies

**Core Libraries**
- `@neondatabase/serverless`: PostgreSQL client for serverless environments (Neon Database)
- `drizzle-orm` & `drizzle-kit`: Type-safe ORM and migration tools
- `pcap-parser`: Binary PCAP file parsing
- `multer`: Multipart form data handling for file uploads
- `connect-pg-simple`: PostgreSQL session store for Express (currently unused)

**UI Component Libraries**
- `@radix-ui/*`: 20+ accessible UI primitives (dialogs, dropdowns, tooltips, etc.)
- `cmdk`: Command palette component
- `react-hook-form` & `@hookform/resolvers`: Form management with validation
- `class-variance-authority`: Type-safe variant management for components
- `clsx` & `tailwind-merge`: Utility for conditional className composition

**Development Tools**
- `@replit/vite-plugin-*`: Replit-specific development enhancements (cartographer, dev banner, runtime error overlay)
- Custom Vite middleware mode for Express integration during development
- Production build uses esbuild for server bundling and Vite for client assets

**Build & Deployment**
- Development: `tsx` runs TypeScript server directly with Vite middleware
- Production build: Vite bundles client to `dist/public`, esbuild bundles server to `dist`
- Separate TypeScript compilation checking via `tsc --noEmit`
- Database schema push via `drizzle-kit push` command