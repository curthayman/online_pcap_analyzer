# PCAP Analyzer Design Guidelines

## Design Approach

**Selected System:** Hybrid approach drawing from Material Design and Carbon Design System
- **Material Design** for interactive components, elevation, and micro-interactions
- **Carbon Design** for data visualization, table structures, and enterprise-grade information density
- **Rationale:** This technical tool serves network analysts and security professionals who need efficient data access and clear visual hierarchy for complex network information

**Reference Inspiration:** Linear (for clean data presentation), Wireshark (for technical familiarity), and apackets.com's existing professional aesthetic

## Core Design Principles

1. **Information Clarity:** Technical data must be scannable and hierarchically organized
2. **Professional Confidence:** Convey reliability and precision expected in security tools
3. **Efficient Workflows:** Minimize clicks between upload, analysis, and insights
4. **Visual Distinction:** Use color strategically to differentiate protocols and data types

---

## Color Palette

### Light Mode
- **Primary:** 220 85% 45% (Deep blue for trust and technical precision)
- **Primary Hover:** 220 85% 38%
- **Secondary:** 200 20% 25% (Neutral slate for text and borders)
- **Background:** 0 0% 98%
- **Surface:** 0 0% 100%
- **Surface Elevated:** 0 0% 100% with subtle shadow
- **Border:** 220 15% 88%

### Dark Mode
- **Primary:** 220 90% 60%
- **Primary Hover:** 220 90% 68%
- **Secondary:** 200 10% 75%
- **Background:** 220 15% 10%
- **Surface:** 220 12% 14%
- **Surface Elevated:** 220 12% 18%
- **Border:** 220 15% 22%

### Semantic Colors
- **Success:** 142 70% 45% (File extraction, successful analysis)
- **Warning:** 38 92% 50% (Certificate expiration, anomalies)
- **Danger:** 0 70% 50% (Security threats, malicious activity)
- **Info:** 200 85% 55% (Network information, DNS queries)

### Protocol-Specific Accent Colors
- **HTTP:** 280 65% 58% (Purple)
- **DNS:** 170 75% 42% (Teal)
- **WiFi/WPA:** 30 80% 55% (Orange)
- **SMB:** 340 70% 50% (Pink-red)
- **ARP:** 90 60% 48% (Green)
- **SSL/TLS:** 260 70% 50% (Indigo)

---

## Typography

**Font Stack:** "Inter" (primary), system-ui, sans-serif
- **Source:** Google Fonts CDN
- **Why:** Excellent legibility at small sizes, technical feel, wide character support for network data

### Type Scale
- **Display (Hero):** 48px / 700 / -0.02em tracking / 1.1 line-height
- **H1 (Page Headers):** 32px / 600 / -0.015em / 1.2
- **H2 (Section Headers):** 24px / 600 / -0.01em / 1.3
- **H3 (Card Headers):** 18px / 600 / normal / 1.4
- **Body Large:** 16px / 400 / normal / 1.5
- **Body (Default):** 14px / 400 / normal / 1.5
- **Body Small:** 13px / 400 / normal / 1.4
- **Code/Monospace:** "JetBrains Mono", monospace / 13px / 400

**Monospace Font:** "JetBrains Mono" for IP addresses, MAC addresses, hashes, hex values

---

## Layout System

**Tailwind Spacing Units:** Primary units are 2, 4, 6, 8, 12, 16, 20
- **Compact spacing:** 2-4 units for dense data tables and protocol lists
- **Standard spacing:** 6-8 units for card padding and section separation
- **Generous spacing:** 12-20 units for major page sections

**Container Widths:**
- **Max Content Width:** max-w-7xl (1280px)
- **Dashboard Panels:** max-w-6xl
- **Data Tables:** Full width with horizontal scroll if needed

**Grid Patterns:**
- **Feature Cards:** grid-cols-1 md:grid-cols-2 lg:grid-cols-3
- **Protocol Analysis Panels:** grid-cols-1 lg:grid-cols-2 (split view)
- **Stats/Metrics:** grid-cols-2 md:grid-cols-4

---

## Component Library

### Navigation
- **Top Bar:** Fixed header with logo, upload button (primary CTA), and navigation links
- **Tabs:** Material Design tabs for switching between protocol views (HTTP, DNS, WiFi, etc.)
- **Breadcrumbs:** For navigating between upload → analysis → specific protocol details

### Cards & Panels
- **Analysis Cards:** Elevated surface with 8px border-radius, subtle shadow, 16-24px padding
- **Protocol Cards:** Color-coded left border (4px) indicating protocol type
- **Stat Cards:** Compact display with large numbers, small labels, icon indicators

### Data Display
- **Tables:** Dense, zebra-striped rows, sticky headers, sortable columns, 12px row padding
- **Network Graph:** Interactive force-directed graph with draggable nodes, colored by device type
- **Timeline View:** Vertical timeline for packet sequences with timestamps
- **Tree View:** Collapsible hierarchical data for packet dissection

### Forms & Input
- **File Upload:** Large drag-and-drop zone (300px height) with dashed border, icon, and descriptive text
- **Search/Filter:** Persistent search bar with instant filtering, clear button
- **Select Dropdowns:** Material Design style with checkboxes for multi-select filters

### Buttons
- **Primary:** Solid background with primary color, 10px padding, medium font-weight
- **Secondary:** Outline style with 2px border
- **Text Buttons:** For low-priority actions in dense interfaces
- **Icon Buttons:** 40x40px touch target for toolbar actions

### Data Visualization
- **Charts:** Use Chart.js for traffic flow over time, protocol distribution pie charts
- **Network Map:** D3.js or Vis.js force-directed graph with zoom/pan controls
- **Progress Indicators:** Linear progress for file analysis, circular for loading states

### Icons
**Library:** Heroicons (outline for general UI, solid for filled states)
- **Protocol Icons:** Custom colored badges with protocol abbreviations (HTTP, DNS, etc.)
- **Device Icons:** Router, computer, phone, server icons for network map

---

## Layout Specifications

### Landing/Upload Page
**Hero Section:** 60vh height with centered content
- **Background:** Subtle animated grid pattern or network node visualization
- **Content:** Large headline "Analyze Network Traffic Instantly", subheadline, primary upload button, feature badges
- **No Hero Image:** Instead use abstract network visualization background

**Feature Grid:** 3-column layout showcasing 9 core features with icons, titles, and short descriptions

**CTA Section:** Prominent upload zone with "Drag PCAP file or click to browse" (400px height)

### Analysis Dashboard
**Layout:** Two-column grid on large screens
- **Left Sidebar (30%):** Summary stats, detected protocols list, quick filters
- **Main Content (70%):** Tabbed protocol analysis views, network graph, data tables

**Sticky Elements:** Top navigation and protocol tabs remain visible during scroll

### Protocol Detail Views
**Split Layout:**
- **Top:** Summary cards (4-column grid showing key metrics)
- **Middle:** Interactive visualization (network map, timeline, or chart)
- **Bottom:** Detailed data table with all packets/requests

---

## Images

### Hero Background
**Description:** Abstract network topology visualization - semi-transparent white/blue nodes connected by flowing lines on dark background, subtle animation showing data packets traveling between nodes
**Placement:** Full-width background behind hero content, opacity 15-20%

### Feature Section Icons
**Description:** Use Heroicons for feature illustrations - no photographic images needed
**Examples:** 
- Globe icon for network map
- Shield icon for security analysis
- Document icon for file extraction
- Key icon for password recovery

### Empty States
**Description:** Simple line illustrations of empty network graphs, empty file folders
**Placement:** When no PCAP file loaded or no data found in analysis

---

## Animations

**Minimal approach - use sparingly:**
- **File Upload:** Gentle scale-up on drag-over (scale-105)
- **Network Graph:** Smooth node position transitions (300ms ease)
- **Tab Switching:** Fade transition between protocol views (200ms)
- **Loading States:** Pulsing skeleton screens for data tables

**Avoid:** Excessive hover effects, parallax scrolling, decorative animations

---

## Accessibility & Interaction

- **Keyboard Navigation:** All interactive elements accessible via Tab key
- **Focus States:** 2px outline with 2px offset in primary color
- **Color Contrast:** Maintain WCAG AA compliance (4.5:1 for text)
- **Tooltips:** Appear on hover for technical terms and abbreviated protocol names
- **Dark Mode:** Consistent implementation across all components, including form inputs and data tables