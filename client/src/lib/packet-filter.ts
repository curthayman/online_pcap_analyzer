import type { Packet } from "@shared/schema";

/**
 * Filter expression parser for Wireshark-like syntax
 * Supports: ip.src, ip.dst, tcp.port, udp.port, protocol, contains, matches
 */

export interface FilterExpression {
  field: string;
  operator: string;
  value: string;
}

export function parseFilter(filterString: string): FilterExpression | null {
  if (!filterString.trim()) return null;

  // Support various operators
  const operators = ['==', '!=', 'contains', 'matches', '>=', '<=', '>', '<'];

  for (const op of operators) {
    const parts = filterString.split(op).map(s => s.trim());
    if (parts.length === 2) {
      return {
        field: parts[0],
        operator: op,
        value: parts[1].replace(/['"]/g, ''), // Remove quotes
      };
    }
  }

  // Simple keyword search (search in all fields)
  return {
    field: '*',
    operator: 'contains',
    value: filterString.trim(),
  };
}

export function matchPacket(packet: Packet, filter: FilterExpression | null): boolean {
  if (!filter) return true;

  const { field, operator, value } = filter;

  // Get field value from packet
  let packetValue: string = '';

  if (field === '*') {
    // Search all fields
    packetValue = JSON.stringify(packet).toLowerCase();
    return packetValue.includes(value.toLowerCase());
  }

  switch (field.toLowerCase()) {
    case 'ip.src':
    case 'source':
    case 'src':
      packetValue = packet.sourceIP || '';
      break;
    case 'ip.dst':
    case 'destination':
    case 'dst':
      packetValue = packet.destIP || '';
      break;
    case 'ip.addr':
    case 'ip':
      packetValue = `${packet.sourceIP} ${packet.destIP}`;
      break;
    case 'tcp.port':
    case 'udp.port':
    case 'port':
      packetValue = `${packet.sourcePort || ''} ${packet.destPort || ''}`;
      break;
    case 'tcp.srcport':
    case 'udp.srcport':
    case 'sport':
      packetValue = String(packet.sourcePort || '');
      break;
    case 'tcp.dstport':
    case 'udp.dstport':
    case 'dport':
      packetValue = String(packet.destPort || '');
      break;
    case 'protocol':
    case 'proto':
      packetValue = packet.protocol || '';
      break;
    case 'info':
      packetValue = packet.info || '';
      break;
    case 'length':
    case 'len':
      packetValue = String(packet.length || 0);
      break;
    default:
      return false;
  }

  // Apply operator
  switch (operator) {
    case '==':
      return packetValue.toLowerCase() === value.toLowerCase();
    case '!=':
      return packetValue.toLowerCase() !== value.toLowerCase();
    case 'contains':
      return packetValue.toLowerCase().includes(value.toLowerCase());
    case 'matches':
      try {
        const regex = new RegExp(value, 'i');
        return regex.test(packetValue);
      } catch {
        return false;
      }
    case '>':
      return Number(packetValue) > Number(value);
    case '<':
      return Number(packetValue) < Number(value);
    case '>=':
      return Number(packetValue) >= Number(value);
    case '<=':
      return Number(packetValue) <= Number(value);
    default:
      return false;
  }
}

export function filterPackets(packets: Packet[], filterString: string): Packet[] {
  const filter = parseFilter(filterString);
  if (!filter) return packets;

  return packets.filter(packet => matchPacket(packet, filter));
}

// Quick filter presets
export const QUICK_FILTERS = [
  { label: 'HTTP', filter: 'protocol == HTTP', icon: '🌐' },
  { label: 'DNS', filter: 'protocol == DNS', icon: '🔎' },
  { label: 'TCP', filter: 'protocol == TCP', icon: '🔌' },
  { label: 'UDP', filter: 'protocol == UDP', icon: '📡' },
  { label: 'ICMP', filter: 'protocol == ICMP', icon: '🏓' },
  { label: 'Large (>1000)', filter: 'length > 1000', icon: '📦' },
  { label: 'Port 443', filter: 'port contains 443', icon: '🔒' },
  { label: 'Port 80', filter: 'port contains 80', icon: '🌍' },
];

// Filter history management
const STORAGE_KEY = 'packet-filter-history';
const MAX_HISTORY = 10;

export function saveFilterToHistory(filter: string): void {
  if (!filter.trim()) return;

  const history = getFilterHistory();
  const updated = [filter, ...history.filter(f => f !== filter)].slice(0, MAX_HISTORY);

  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch (e) {
    console.warn('Failed to save filter history:', e);
  }
}

export function getFilterHistory(): string[] {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored ? JSON.parse(stored) : [];
  } catch {
    return [];
  }
}

export function clearFilterHistory(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (e) {
    console.warn('Failed to clear filter history:', e);
  }
}
