import { createReadStream } from 'fs';
import pcapp from 'pcap-parser';
import type {
  AnalysisResult,
  NetworkNode,
  NetworkConnection,
  HttpTransaction,
  DnsQuery,
  ExtractedFile,
  Credential,
  Packet,
  PcapStatistics,
} from '@shared/schema';
import { randomUUID } from 'crypto';

interface PcapPacket {
  header: {
    timestampSeconds: number;
    timestampMicroseconds: number;
    capturedLength: number;
    originalLength: number;
  };
  data: Buffer;
}

export async function analyzePcapFile(
  filePath: string,
  fileName: string,
  fileSize: number,
  analysisId: string,
  progressCallback?: (progress: number, message: string, step?: string) => void
): Promise<AnalysisResult> {
  return new Promise((resolve, reject) => {
    const packets: Packet[] = [];
    const nodes = new Map<string, NetworkNode>();
    const connections = new Map<string, NetworkConnection>();
    const httpTransactions: HttpTransaction[] = [];
    const dnsQueries: DnsQuery[] = [];
    const extractedFiles: ExtractedFile[] = [];
    const credentials: Credential[] = [];
    const protocolCount = new Map<string, number>();

    let totalBytes = 0;
    let startTime = 0;
    let endTime = 0;
    let packetCount = 0;

    progressCallback?.(10, 'Starting PCAP analysis...', 'parsing');

    const parser = pcapp.parse(filePath);

    parser.on('packet', (rawPacket: PcapPacket) => {
      try {
        const timestamp = rawPacket.header.timestampSeconds * 1000 + 
                         rawPacket.header.timestampMicroseconds / 1000;
        
        if (startTime === 0) startTime = timestamp;
        endTime = timestamp;
        totalBytes += rawPacket.header.capturedLength;
        packetCount++;

        // Report progress every 100 packets
        if (packetCount % 100 === 0) {
          const progress = Math.min(20 + (packetCount / 100) * 2, 70);
          progressCallback?.(progress, `Parsed ${packetCount} packets...`, 'analyzing');
        }

        const packetData = parsePacket(rawPacket.data, timestamp);
        if (packetData) {
          packets.push(packetData);
          
          // Track protocol distribution
          const count = protocolCount.get(packetData.protocol) || 0;
          protocolCount.set(packetData.protocol, count + 1);

          // Track nodes
          if (packetData.sourceIP) {
            addOrUpdateNode(nodes, packetData.sourceIP, packetData.protocol);
          }
          if (packetData.destIP) {
            addOrUpdateNode(nodes, packetData.destIP, packetData.protocol);
          }

          // Track connections
          if (packetData.sourceIP && packetData.destIP) {
            addOrUpdateConnection(
              connections,
              packetData.sourceIP,
              packetData.destIP,
              packetData.protocol,
              packetData.length
            );
          }

          // Extract HTTP data
          if (packetData.protocol === 'HTTP') {
            const http = parseHttp(rawPacket.data, packetData, timestamp);
            if (http) {
              httpTransactions.push(http);
              
              // Extract credentials from HTTP
              const cred = extractHttpCredentials(http, timestamp);
              if (cred) credentials.push(cred);

              // Extract files from HTTP
              const file = extractHttpFile(http, timestamp);
              if (file) extractedFiles.push(file);
            }
          }

          // Extract DNS data
          if (packetData.protocol === 'DNS') {
            const dns = parseDns(rawPacket.data, packetData, timestamp);
            if (dns) dnsQueries.push(dns);
          }

          // Extract FTP/Telnet credentials
          if (packetData.protocol === 'FTP' || packetData.protocol === 'TELNET') {
            const cred = extractPlaintextCredentials(rawPacket.data, packetData, timestamp);
            if (cred) credentials.push(cred);
          }
        }
      } catch (err) {
        // Skip malformed packets
      }
    });

    parser.on('end', () => {
      progressCallback?.(75, 'Building network topology...', 'finalizing');
      
      const duration = (endTime - startTime) / 1000;
      
      // Calculate top talkers
      const nodePacketCounts = new Map<string, number>();
      packets.forEach(p => {
        if (p.sourceIP) {
          nodePacketCounts.set(p.sourceIP, (nodePacketCounts.get(p.sourceIP) || 0) + 1);
        }
      });
      
      const topTalkers = Array.from(nodePacketCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => ({
          ip,
          packets: count,
          bytes: connections.get(ip)?.bytes || 0,
        }));

      progressCallback?.(85, 'Generating statistics...', 'finalizing');

      // Create timeline data (simplified)
      const timelineData = createTimeline(packets, startTime, endTime);

      const statistics: PcapStatistics = {
        totalPackets: packets.length,
        totalBytes,
        duration,
        protocolDistribution: Object.fromEntries(protocolCount),
        topTalkers,
        timelineData,
      };

      progressCallback?.(95, 'Finalizing analysis...', 'finalizing');

      const result: AnalysisResult = {
        analysis: {
          id: analysisId,
          fileName,
          fileSize,
          uploadedAt: new Date().toISOString(),
          status: 'completed',
          totalPackets: packets.length,
          duration,
          protocols: Array.from(protocolCount.keys()),
        },
        statistics,
        nodes: Array.from(nodes.values()),
        connections: Array.from(connections.values()),
        httpTransactions,
        dnsQueries,
        extractedFiles,
        credentials,
        packets: packets.slice(0, 1000), // Limit to first 1000 packets
      };

      progressCallback?.(100, 'Analysis completed!', 'completed');

      resolve(result);
    });

    parser.on('error', (err: Error) => {
      reject(err);
    });
  });
}

function parsePacket(data: Buffer, timestamp: number): Packet | null {
  try {
    // Parse Ethernet header (14 bytes)
    if (data.length < 14) return null;

    const etherType = data.readUInt16BE(12);
    
    // IPv4
    if (etherType === 0x0800) {
      if (data.length < 34) return null;
      
      const ipHeader = data.slice(14);
      const protocol = ipHeader[9];
      const sourceIP = `${ipHeader[12]}.${ipHeader[13]}.${ipHeader[14]}.${ipHeader[15]}`;
      const destIP = `${ipHeader[16]}.${ipHeader[17]}.${ipHeader[18]}.${ipHeader[19]}`;
      
      const ipHeaderLength = (ipHeader[0] & 0x0f) * 4;
      const transportData = ipHeader.slice(ipHeaderLength);
      
      let protocolName = 'Unknown';
      let sourcePort: number | undefined;
      let destPort: number | undefined;
      let info = '';

      if (protocol === 6) { // TCP
        protocolName = 'TCP';
        if (transportData.length >= 4) {
          sourcePort = transportData.readUInt16BE(0);
          destPort = transportData.readUInt16BE(2);
          
          // Identify application protocols
          if (destPort === 80 || sourcePort === 80) protocolName = 'HTTP';
          else if (destPort === 53 || sourcePort === 53) protocolName = 'DNS';
          else if (destPort === 21 || sourcePort === 21) protocolName = 'FTP';
          else if (destPort === 23 || sourcePort === 23) protocolName = 'TELNET';
        }
      } else if (protocol === 17) { // UDP
        protocolName = 'UDP';
        if (transportData.length >= 4) {
          sourcePort = transportData.readUInt16BE(0);
          destPort = transportData.readUInt16BE(2);
          
          if (destPort === 53 || sourcePort === 53) protocolName = 'DNS';
        }
      } else if (protocol === 1) {
        protocolName = 'ICMP';
      }

      return {
        id: randomUUID(),
        timestamp: new Date(timestamp).toISOString(),
        protocol: protocolName,
        sourceIP,
        destIP,
        sourcePort,
        destPort,
        length: data.length,
        info,
      };
    }

    return null;
  } catch {
    return null;
  }
}

function addOrUpdateNode(
  nodes: Map<string, NetworkNode>,
  ip: string,
  protocol: string
) {
  let node = nodes.get(ip);
  if (!node) {
    node = {
      id: randomUUID(),
      ipAddress: ip,
      nodeType: determineNodeType(ip),
      packetCount: 0,
      protocols: [],
    };
    nodes.set(ip, node);
  }
  
  node.packetCount++;
  if (!node.protocols.includes(protocol)) {
    node.protocols.push(protocol);
  }
}

function determineNodeType(ip: string): 'router' | 'server' | 'client' | 'unknown' {
  const parts = ip.split('.');
  const lastOctet = parseInt(parts[3]);
  
  if (lastOctet === 1 || lastOctet === 254) return 'router';
  if (lastOctet < 50) return 'server';
  return 'client';
}

function addOrUpdateConnection(
  connections: Map<string, NetworkConnection>,
  sourceIP: string,
  destIP: string,
  protocol: string,
  bytes: number
) {
  const key = `${sourceIP}-${destIP}-${protocol}`;
  let conn = connections.get(key);
  
  if (!conn) {
    conn = {
      id: randomUUID(),
      sourceIP,
      destIP,
      protocol,
      packetCount: 0,
      bytes: 0,
    };
    connections.set(key, conn);
  }
  
  conn.packetCount++;
  conn.bytes += bytes;
}

function parseHttp(data: Buffer, packet: Packet, timestamp: number): HttpTransaction | null {
  try {
    const text = data.toString('utf8');
    const httpMatch = text.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/);
    
    if (httpMatch) {
      const method = httpMatch[1];
      const url = httpMatch[2];
      const headers: Record<string, string> = {};
      
      const headerLines = text.split('\r\n');
      for (let i = 1; i < headerLines.length; i++) {
        const line = headerLines[i];
        if (!line) break;
        const colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
          const key = line.substring(0, colonIndex).trim();
          const value = line.substring(colonIndex + 1).trim();
          headers[key] = value;
        }
      }
      
      return {
        id: randomUUID(),
        timestamp: new Date(timestamp).toISOString(),
        method,
        url,
        host: headers['Host'],
        headers,
        sourceIP: packet.sourceIP,
        destIP: packet.destIP,
      };
    }
    
    // Check for HTTP response
    const responseMatch = text.match(/^HTTP\/[\d.]+\s+(\d+)/);
    if (responseMatch) {
      const statusCode = parseInt(responseMatch[1]);
      const headers: Record<string, string> = {};
      
      const headerLines = text.split('\r\n');
      for (let i = 1; i < headerLines.length; i++) {
        const line = headerLines[i];
        if (!line) break;
        const colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
          const key = line.substring(0, colonIndex).trim();
          const value = line.substring(colonIndex + 1).trim();
          headers[key] = value;
        }
      }
      
      return {
        id: randomUUID(),
        timestamp: new Date(timestamp).toISOString(),
        method: 'RESPONSE',
        url: '/',
        headers,
        statusCode,
        responseHeaders: headers,
        sourceIP: packet.sourceIP,
        destIP: packet.destIP,
      };
    }
    
    return null;
  } catch {
    return null;
  }
}

function parseDns(data: Buffer, packet: Packet, timestamp: number): DnsQuery | null {
  try {
    // Simplified DNS parsing - look for domain names
    const text = data.toString('utf8', 0, Math.min(data.length, 200));
    const domainMatch = text.match(/([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}/);
    
    if (domainMatch) {
      return {
        id: randomUUID(),
        timestamp: new Date(timestamp).toISOString(),
        queryType: 'A',
        domain: domainMatch[0],
        response: [],
        sourceIP: packet.sourceIP,
        destIP: packet.destIP,
      };
    }
    
    return null;
  } catch {
    return null;
  }
}

function extractHttpCredentials(http: HttpTransaction, timestamp: number): Credential | null {
  const authHeader = http.headers['Authorization'];
  if (authHeader && authHeader.startsWith('Basic ')) {
    try {
      const base64 = authHeader.substring(6);
      const decoded = Buffer.from(base64, 'base64').toString('utf8');
      const [username, password] = decoded.split(':');
      
      if (username && password) {
        return {
          id: randomUUID(),
          protocol: 'HTTP',
          username,
          password,
          type: 'plaintext',
          timestamp: new Date(timestamp).toISOString(),
          sourceIP: http.sourceIP,
          destIP: http.destIP,
        };
      }
    } catch {
      // Invalid base64
    }
  }
  
  return null;
}

function extractHttpFile(http: HttpTransaction, timestamp: number): ExtractedFile | null {
  const contentType = http.responseHeaders?.['Content-Type'];
  const contentDisposition = http.responseHeaders?.['Content-Disposition'];
  
  if (contentType && http.responseBody) {
    let fileName = 'unknown';
    
    if (contentDisposition) {
      const match = contentDisposition.match(/filename="?([^"]+)"?/);
      if (match) fileName = match[1];
    } else if (http.url) {
      const urlParts = http.url.split('/');
      fileName = urlParts[urlParts.length - 1] || 'index.html';
    }
    
    return {
      id: randomUUID(),
      fileName,
      fileType: contentType.split(';')[0],
      fileSize: http.responseBody.length,
      protocol: 'HTTP',
      sourceIP: http.sourceIP,
      destIP: http.destIP,
      timestamp: new Date(timestamp).toISOString(),
      data: Buffer.from(http.responseBody).toString('base64'),
      mimeType: contentType,
    };
  }
  
  return null;
}

function extractPlaintextCredentials(data: Buffer, packet: Packet, timestamp: number): Credential | null {
  try {
    const text = data.toString('utf8');
    
    // FTP USER/PASS
    if (packet.protocol === 'FTP') {
      const userMatch = text.match(/USER\s+([^\r\n]+)/);
      const passMatch = text.match(/PASS\s+([^\r\n]+)/);
      
      if (userMatch || passMatch) {
        return {
          id: randomUUID(),
          protocol: 'FTP',
          username: userMatch ? userMatch[1] : 'unknown',
          password: passMatch ? passMatch[1] : 'unknown',
          type: 'plaintext',
          timestamp: new Date(timestamp).toISOString(),
          sourceIP: packet.sourceIP,
        };
      }
    }
    
    return null;
  } catch {
    return null;
  }
}

function createTimeline(packets: Packet[], startTime: number, endTime: number) {
  const buckets = 20;
  const duration = endTime - startTime;
  const bucketSize = duration / buckets;
  const timeline: { timestamp: string; packets: number }[] = [];
  
  for (let i = 0; i < buckets; i++) {
    const bucketTime = startTime + i * bucketSize;
    const bucketEnd = bucketTime + bucketSize;
    const count = packets.filter(p => {
      const time = new Date(p.timestamp).getTime();
      return time >= bucketTime && time < bucketEnd;
    }).length;
    
    timeline.push({
      timestamp: new Date(bucketTime).toISOString(),
      packets: count,
    });
  }
  
  return timeline;
}
