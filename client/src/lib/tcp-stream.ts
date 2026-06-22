import type { Packet } from "@shared/schema";

export interface TcpStreamPacket {
  packet: Packet;
  direction: 'client' | 'server';
  sequenceNumber?: number;
}

export interface TcpStream {
  id: string;
  clientIP: string;
  serverIP: string;
  clientPort: number;
  serverPort: number;
  packets: TcpStreamPacket[];
  totalBytes: number;
  startTime: string;
  endTime: string;
}

/**
 * Reconstruct TCP streams from a collection of packets
 */
export function reconstructTcpStream(
  packets: Packet[],
  sourceIP: string,
  destIP: string,
  sourcePort: number,
  destPort: number
): TcpStream | null {
  // Filter packets for this specific conversation
  const streamPackets = packets.filter((p) => {
    const isForward =
      p.sourceIP === sourceIP &&
      p.destIP === destIP &&
      p.sourcePort === sourcePort &&
      p.destPort === destPort;

    const isReverse =
      p.sourceIP === destIP &&
      p.destIP === sourceIP &&
      p.sourcePort === destPort &&
      p.destPort === sourcePort;

    return (isForward || isReverse) && p.protocol === 'TCP';
  });

  if (streamPackets.length === 0) {
    return null;
  }

  // Sort by timestamp
  streamPackets.sort((a, b) => {
    return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
  });

  // Determine which is client/server (client typically initiates)
  const clientIP = sourceIP;
  const serverIP = destIP;
  const clientPort = sourcePort;
  const serverPort = destPort;

  // Build stream packets with direction
  const tcpStreamPackets: TcpStreamPacket[] = streamPackets.map((packet) => ({
    packet,
    direction:
      packet.sourceIP === clientIP && packet.sourcePort === clientPort
        ? 'client'
        : 'server',
  }));

  const totalBytes = streamPackets.reduce((sum, p) => sum + p.length, 0);

  return {
    id: `${clientIP}:${clientPort}-${serverIP}:${serverPort}`,
    clientIP,
    serverIP,
    clientPort,
    serverPort,
    packets: tcpStreamPackets,
    totalBytes,
    startTime: streamPackets[0].timestamp,
    endTime: streamPackets[streamPackets.length - 1].timestamp,
  };
}

/**
 * Find all unique TCP conversations in a packet list
 */
export function findTcpConversations(packets: Packet[]): Array<{
  sourceIP: string;
  destIP: string;
  sourcePort: number;
  destPort: number;
  packetCount: number;
}> {
  const conversations = new Map<string, {
    sourceIP: string;
    destIP: string;
    sourcePort: number;
    destPort: number;
    packetCount: number;
  }>();

  packets.forEach((packet) => {
    if (packet.protocol !== 'TCP' || !packet.sourcePort || !packet.destPort) {
      return;
    }

    // Create bidirectional key (normalize so A->B and B->A have same key)
    const key1 = `${packet.sourceIP}:${packet.sourcePort}-${packet.destIP}:${packet.destPort}`;
    const key2 = `${packet.destIP}:${packet.destPort}-${packet.sourceIP}:${packet.sourcePort}`;

    const existingKey = conversations.has(key1) ? key1 : conversations.has(key2) ? key2 : null;

    if (existingKey) {
      const conv = conversations.get(existingKey)!;
      conv.packetCount++;
    } else {
      conversations.set(key1, {
        sourceIP: packet.sourceIP,
        destIP: packet.destIP,
        sourcePort: packet.sourcePort,
        destPort: packet.destPort,
        packetCount: 1,
      });
    }
  });

  return Array.from(conversations.values())
    .sort((a, b) => b.packetCount - a.packetCount);
}

/**
 * Export TCP stream as text
 */
export function exportStreamAsText(stream: TcpStream): string {
  let output = '';
  output += '='.repeat(80) + '\n';
  output += `TCP Stream: ${stream.clientIP}:${stream.clientPort} <-> ${stream.serverIP}:${stream.serverPort}\n`;
  output += `Packets: ${stream.packets.length} | Bytes: ${stream.totalBytes}\n`;
  output += `Start: ${stream.startTime}\n`;
  output += `End: ${stream.endTime}\n`;
  output += '='.repeat(80) + '\n\n';

  stream.packets.forEach((sp, index) => {
    const direction = sp.direction === 'client' ? '>>>' : '<<<';
    const label = sp.direction === 'client' ? 'CLIENT' : 'SERVER';

    output += `[${index + 1}] ${direction} ${label} ${direction}\n`;
    output += `Time: ${sp.packet.timestamp}\n`;
    output += `Length: ${sp.packet.length} bytes\n`;

    if (sp.packet.info) {
      output += `Info: ${sp.packet.info}\n`;
    }

    output += '-'.repeat(80) + '\n\n';
  });

  return output;
}
