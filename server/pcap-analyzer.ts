import { createReadStream } from 'fs';
import { readFile } from 'fs/promises';
import pcapp from 'pcap-parser';
import PCAPNGParser from 'pcap-ng-parser';
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
  WiFiFrame,
  WiFiNetwork,
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

async function detectFileFormat(filePath: string): Promise<'pcap' | 'pcapng'> {
  const buffer = await readFile(filePath);
  const magicNumber = buffer.readUInt32BE(0);
  
  // PCAPNG magic number: 0x0a0d0d0a
  if (magicNumber === 0x0a0d0d0a) {
    return 'pcapng';
  }
  
  // PCAP magic numbers: 0xa1b2c3d4 (big-endian) or 0xd4c3b2a1 (little-endian)
  if (magicNumber === 0xa1b2c3d4 || magicNumber === 0xd4c3b2a1) {
    return 'pcap';
  }
  
  // Try little-endian read
  const magicNumberLE = buffer.readUInt32LE(0);
  if (magicNumberLE === 0x0a0d0d0a) {
    return 'pcapng';
  }
  
  // Default to pcap for backwards compatibility
  return 'pcap';
}

export async function analyzePcapFile(
  filePath: string,
  fileName: string,
  fileSize: number,
  analysisId: string,
  progressCallback?: (progress: number, message: string, step?: string) => void
): Promise<AnalysisResult> {
  // Detect file format
  const format = await detectFileFormat(filePath);
  
  if (format === 'pcapng') {
    return analyzePcapngFile(filePath, fileName, fileSize, analysisId, progressCallback);
  }
  
  return new Promise((resolve, reject) => {
    const packets: Packet[] = [];
    const nodes = new Map<string, NetworkNode>();
    const connections = new Map<string, NetworkConnection>();
    const httpTransactions: HttpTransaction[] = [];
    const dnsQueries: DnsQuery[] = [];
    const extractedFiles: ExtractedFile[] = [];
    const credentials: Credential[] = [];
    const protocolCount = new Map<string, number>();
    const wifiFrames: WiFiFrame[] = [];
    const wifiNetworks = new Map<string, WiFiNetwork>();

    let totalBytes = 0;
    let startTime = 0;
    let endTime = 0;
    let packetCount = 0;
    let linkLayerType = 1; // Default to Ethernet

    progressCallback?.(10, 'Starting PCAP analysis...', 'parsing');

    const parser = pcapp.parse(filePath);

    parser.on('globalHeader', (header: any) => {
      linkLayerType = header.linkLayerType || 1;
      console.log(`PCAP Link Layer Type: ${linkLayerType}`);
    });

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

        const packetData = parsePacket(rawPacket.data, timestamp, linkLayerType);
        if (packetData) {
          packets.push(packetData);
          
          // Handle WiFi frames
          if (packetData.wifiFrame) {
            wifiFrames.push(packetData.wifiFrame);
            
            // Track WiFi networks
            if (packetData.wifiFrame.bssid && packetData.wifiFrame.ssid) {
              addOrUpdateWiFiNetwork(
                wifiNetworks,
                packetData.wifiFrame.bssid,
                packetData.wifiFrame.ssid,
                packetData.wifiFrame
              );
            }
          }
          
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
          if (packetData.protocol === 'HTTP' && packetData.payload) {
            const http = parseHttp(packetData.payload, packetData, timestamp);
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
        wifiFrames: wifiFrames.length > 0 ? wifiFrames.slice(0, 1000) : undefined,
        wifiNetworks: wifiNetworks.size > 0 ? Array.from(wifiNetworks.values()) : undefined,
      };

      progressCallback?.(100, 'Analysis completed!', 'completed');

      resolve(result);
    });

    parser.on('error', (err: Error) => {
      reject(err);
    });
  });
}

async function analyzePcapngFile(
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
    const wifiFrames: WiFiFrame[] = [];
    const wifiNetworks = new Map<string, WiFiNetwork>();

    let totalBytes = 0;
    let startTime = 0;
    let endTime = 0;
    let packetCount = 0;

    progressCallback?.(10, 'Starting PCAPNG analysis...', 'parsing');

    const parser = new PCAPNGParser();
    const fileStream = createReadStream(filePath);

    let hasEnded = false;
    const completeAnalysis = () => {
      if (hasEnded) return;
      hasEnded = true;
      
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
        wifiFrames: wifiFrames.length > 0 ? wifiFrames.slice(0, 1000) : undefined,
        wifiNetworks: wifiNetworks.size > 0 ? Array.from(wifiNetworks.values()) : undefined,
      };

      progressCallback?.(100, 'Analysis completed!', 'completed');

      resolve(result);
    };

    parser.on('data', (rawPacket: any) => {
        try {
          // PCAPNG packet structure is different from PCAP
          const timestamp = rawPacket.timestamp || Date.now();
          
          if (startTime === 0) startTime = timestamp;
          endTime = timestamp;
          totalBytes += rawPacket.data?.length || 0;
          packetCount++;

          // Report progress every 100 packets
          if (packetCount % 100 === 0) {
            const progress = Math.min(20 + (packetCount / 100) * 2, 70);
            progressCallback?.(progress, `Parsed ${packetCount} packets...`, 'analyzing');
          }

          const packetData = parsePacket(rawPacket.data, timestamp);
          if (packetData) {
            packets.push(packetData);
            
            // Handle WiFi frames
            if (packetData.wifiFrame) {
              wifiFrames.push(packetData.wifiFrame);
              
              // Track WiFi networks
              if (packetData.wifiFrame.bssid && packetData.wifiFrame.ssid) {
                addOrUpdateWiFiNetwork(
                  wifiNetworks,
                  packetData.wifiFrame.bssid,
                  packetData.wifiFrame.ssid,
                  packetData.wifiFrame
                );
              }
            }
            
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
            if (packetData.protocol === 'HTTP' && packetData.payload) {
              const http = parseHttp(packetData.payload, packetData, timestamp);
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
    
    // Listen to both parser and fileStream end events
    parser.on('end', completeAnalysis);
    parser.on('finish', completeAnalysis);
    fileStream.on('end', completeAnalysis);
    fileStream.on('close', completeAnalysis);
    
    parser.on('error', (err: Error) => {
      reject(err);
    });
    
    fileStream.on('error', (err: Error) => {
      reject(err);
    });

    fileStream.pipe(parser);
  });
}

interface ParsedPacket extends Packet {
  payload?: Buffer;
  wifiFrame?: WiFiFrame;
}

function parsePacket(data: Buffer, timestamp: number, linkLayerType: number = 1): ParsedPacket | null {
  try {
    // Check for WiFi (802.11) link layer
    if (linkLayerType === 105 || linkLayerType === 127) {
      return parseWiFiPacket(data, timestamp, linkLayerType);
    }
    
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
      let payload: Buffer | undefined;

      if (protocol === 6) { // TCP
        protocolName = 'TCP';
        if (transportData.length >= 4) {
          sourcePort = transportData.readUInt16BE(0);
          destPort = transportData.readUInt16BE(2);
          
          // Extract TCP payload
          const tcpHeaderLength = ((transportData[12] >> 4) & 0x0f) * 4;
          if (transportData.length > tcpHeaderLength) {
            payload = transportData.slice(tcpHeaderLength);
          }
          
          // Identify application protocols
          if (destPort === 80 || sourcePort === 80) protocolName = 'HTTP';
          else if (destPort === 53 || sourcePort === 53) protocolName = 'DNS';
          else if (destPort === 21 || sourcePort === 21) protocolName = 'FTP';
          else if (destPort === 23 || sourcePort === 23) protocolName = 'TELNET';
          else if (destPort === 1723 || sourcePort === 1723) {
            protocolName = 'PPTP';
            info = 'VPN Traffic';
          }
        }
      } else if (protocol === 17) { // UDP
        protocolName = 'UDP';
        if (transportData.length >= 4) {
          sourcePort = transportData.readUInt16BE(0);
          destPort = transportData.readUInt16BE(2);
          
          if (destPort === 53 || sourcePort === 53) {
            protocolName = 'DNS';
          } else if (destPort === 500 || sourcePort === 500 || destPort === 4500 || sourcePort === 4500) {
            // IKE (IPsec key exchange)
            protocolName = 'IKE';
            info = 'IPsec Key Exchange (VPN)';
          } else if (destPort === 1194 || sourcePort === 1194) {
            // OpenVPN
            protocolName = 'OpenVPN';
            info = 'VPN Traffic';
          } else if (destPort === 51820 || sourcePort === 51820) {
            // WireGuard
            protocolName = 'WireGuard';
            info = 'VPN Traffic';
          } else if (destPort === 1701 || sourcePort === 1701) {
            // L2TP
            protocolName = 'L2TP';
            info = 'VPN Traffic';
          } else if (transportData.length >= 20) {
            // Conservative WebRTC/video call detection
            const udpPayload = transportData.slice(8); // Skip UDP header
            
            // STUN detection - most reliable WebRTC indicator
            if (udpPayload.length >= 20) {
              const messageType = udpPayload.readUInt16BE(0);
              const messageLength = udpPayload.readUInt16BE(2);
              const stunMagic = udpPayload.readUInt32BE(4);
              
              // STUN validation: magic cookie, valid length, known message types
              if (stunMagic === 0x2112A442 && 
                  messageLength >= 0 && 
                  messageLength === (udpPayload.length - 20) &&
                  (messageType === 0x0001 || // Binding Request
                   messageType === 0x0101 || // Binding Response
                   messageType === 0x0003 || // Binding Error Response
                   messageType === 0x0111)) { // Binding Indication
                protocolName = 'STUN';
                info = 'WebRTC NAT Traversal';
              }
            }
          }
        }
      } else if (protocol === 1) {
        protocolName = 'ICMP';
      } else if (protocol === 50) {
        // ESP - Encapsulating Security Payload (IPsec encrypted traffic)
        protocolName = 'ESP';
        info = 'IPsec Encrypted (VPN)';
      } else if (protocol === 47) {
        // GRE - used by PPTP VPN
        protocolName = 'GRE';
        info = 'PPTP VPN Traffic';
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
        payload,
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

function addOrUpdateWiFiNetwork(
  networks: Map<string, WiFiNetwork>,
  bssid: string,
  ssid: string,
  frame: WiFiFrame
) {
  let network = networks.get(bssid);
  
  if (!network) {
    network = {
      id: randomUUID(),
      ssid,
      bssid,
      channel: frame.channel,
      encryption: frame.encrypted ? 'Encrypted' : 'Open',
      signalStrength: frame.signalStrength,
      beaconCount: 0,
      dataFrameCount: 0,
      clientMACs: [],
    };
    networks.set(bssid, network);
  }
  
  // Update network info
  if (frame.frameSubtype === 'Beacon') {
    network.beaconCount++;
  } else if (frame.frameType === 'Data') {
    network.dataFrameCount++;
  }
  
  // Track client MACs
  if (frame.sourceMAC && !network.clientMACs.includes(frame.sourceMAC) && frame.sourceMAC !== bssid) {
    network.clientMACs.push(frame.sourceMAC);
  }
  if (frame.destMAC && !network.clientMACs.includes(frame.destMAC) && frame.destMAC !== bssid) {
    network.clientMACs.push(frame.destMAC);
  }
  
  // Update signal strength if available
  if (frame.signalStrength && (!network.signalStrength || frame.signalStrength > network.signalStrength)) {
    network.signalStrength = frame.signalStrength;
  }
}

function parseWiFiPacket(data: Buffer, timestamp: number, linkLayerType: number): ParsedPacket | null {
  try {
    let offset = 0;
    let channel: number | undefined;
    let signalStrength: number | undefined;
    let dataRate: number | undefined;
    
    // Parse Radiotap header if present (linkLayerType 127)
    if (linkLayerType === 127) {
      if (data.length < 8) return null;
      
      const radiotapLength = data.readUInt16LE(2);
      if (data.length < radiotapLength) return null;
      
      // Parse Radiotap fields
      const presentFlags = data.readUInt32LE(4);
      let radiotapOffset = 8;
      
      // Channel (bit 3)
      if (presentFlags & (1 << 3)) {
        if (radiotapOffset + 4 <= radiotapLength) {
          const freq = data.readUInt16LE(radiotapOffset);
          // Convert frequency to channel (2.4GHz band)
          if (freq >= 2412 && freq <= 2484) {
            channel = Math.floor((freq - 2412) / 5) + 1;
          }
          radiotapOffset += 4;
        }
      }
      
      // Signal strength (bit 5 - dBm antenna signal)
      if (presentFlags & (1 << 5)) {
        if (radiotapOffset + 1 <= radiotapLength) {
          signalStrength = data.readInt8(radiotapOffset);
          radiotapOffset += 1;
        }
      }
      
      // Data rate (bit 2)
      if (presentFlags & (1 << 2)) {
        if (radiotapOffset + 1 <= radiotapLength) {
          dataRate = data.readUInt8(radiotapOffset) * 0.5; // In Mbps
          radiotapOffset += 1;
        }
      }
      
      offset = radiotapLength;
    }
    
    // Parse 802.11 frame
    if (data.length < offset + 24) return null; // Minimum WiFi frame header
    
    const frameControl = data.readUInt16LE(offset);
    const frameType = (frameControl >> 2) & 0x03;
    const frameSubtype = (frameControl >> 4) & 0x0f;
    
    const frameTypeNames = ['Management', 'Control', 'Data', 'Extension'];
    const frameTypeName = frameTypeNames[frameType] || 'Unknown';
    
    const managementSubtypes: { [key: number]: string } = {
      0x00: 'Association Request',
      0x01: 'Association Response',
      0x02: 'Reassociation Request',
      0x03: 'Reassociation Response',
      0x04: 'Probe Request',
      0x05: 'Probe Response',
      0x08: 'Beacon',
      0x09: 'ATIM',
      0x0a: 'Disassociation',
      0x0b: 'Authentication',
      0x0c: 'Deauthentication',
    };
    
    const dataSubtypes: { [key: number]: string } = {
      0x00: 'Data',
      0x01: 'Data + CF-Ack',
      0x02: 'Data + CF-Poll',
      0x03: 'Data + CF-Ack + CF-Poll',
      0x04: 'Null',
      0x08: 'QoS Data',
    };
    
    let frameSubtypeName = 'Unknown';
    if (frameType === 0) {
      frameSubtypeName = managementSubtypes[frameSubtype] || `Management ${frameSubtype}`;
    } else if (frameType === 2) {
      frameSubtypeName = dataSubtypes[frameSubtype] || `Data ${frameSubtype}`;
    } else {
      frameSubtypeName = `Type${frameType} Subtype${frameSubtype}`;
    }
    
    // Parse MAC addresses
    const addr1 = formatMAC(data.slice(offset + 4, offset + 10));
    const addr2 = formatMAC(data.slice(offset + 10, offset + 16));
    const addr3 = formatMAC(data.slice(offset + 16, offset + 22));
    
    // Determine source, dest, BSSID based on frame type
    let sourceMAC: string | undefined;
    let destMAC: string | undefined;
    let bssid: string | undefined;
    
    const toDS = (frameControl & 0x0100) !== 0;
    const fromDS = (frameControl & 0x0200) !== 0;
    
    if (!toDS && !fromDS) {
      // IBSS or management
      destMAC = addr1;
      sourceMAC = addr2;
      bssid = addr3;
    } else if (!toDS && fromDS) {
      // From AP to station
      destMAC = addr1;
      bssid = addr2;
      sourceMAC = addr3;
    } else if (toDS && !fromDS) {
      // From station to AP
      bssid = addr1;
      sourceMAC = addr2;
      destMAC = addr3;
    } else {
      // WDS (wireless distribution system)
      destMAC = addr1;
      sourceMAC = addr2;
      bssid = addr3;
    }
    
    // Parse SSID from beacon/probe frames
    let ssid: string | undefined;
    let encrypted: boolean | undefined;
    
    if (frameType === 0 && (frameSubtype === 0x08 || frameSubtype === 0x05 || frameSubtype === 0x04)) {
      // Beacon, Probe Response, or Probe Request
      const fixedParams = offset + 24;
      let ieOffset = fixedParams + (frameSubtype === 0x08 ? 12 : frameSubtype === 0x05 ? 12 : 0);
      
      // Parse information elements
      while (ieOffset + 2 < data.length) {
        const elementId = data[ieOffset];
        const elementLen = data[ieOffset + 1];
        
        if (ieOffset + 2 + elementLen > data.length) break;
        
        // SSID element (ID = 0)
        if (elementId === 0 && elementLen > 0) {
          ssid = data.slice(ieOffset + 2, ieOffset + 2 + elementLen).toString('utf8').trim();
        }
        
        // RSN element (ID = 48) or WPA vendor element (ID = 221)
        if (elementId === 48 || (elementId === 221 && elementLen >= 4)) {
          encrypted = true;
        }
        
        ieOffset += 2 + elementLen;
      }
    }
    
    const wifiFrame: WiFiFrame = {
      id: randomUUID(),
      timestamp: new Date(timestamp).toISOString(),
      frameType: frameTypeName,
      frameSubtype: frameSubtypeName,
      sourceMAC,
      destMAC,
      bssid,
      ssid,
      channel,
      signalStrength,
      dataRate,
      encrypted,
      info: `${frameTypeName}: ${frameSubtypeName}`,
    };
    
    return {
      id: randomUUID(),
      timestamp: new Date(timestamp).toISOString(),
      protocol: `WiFi-${frameTypeName}`,
      sourceIP: sourceMAC || 'Unknown',
      destIP: destMAC || 'Unknown',
      length: data.length,
      info: wifiFrame.info,
      wifiFrame,
    };
  } catch {
    return null;
  }
}

function formatMAC(buffer: Buffer): string {
  return Array.from(buffer)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(':')
    .toUpperCase();
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
      let bodyStartIndex = -1;
      
      for (let i = 1; i < headerLines.length; i++) {
        const line = headerLines[i];
        if (!line) {
          bodyStartIndex = i + 1;
          break;
        }
        const colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
          const key = line.substring(0, colonIndex).trim();
          const value = line.substring(colonIndex + 1).trim();
          headers[key] = value;
        }
      }
      
      // Extract request body if present
      let requestBody: string | undefined;
      if (bodyStartIndex > 0 && bodyStartIndex < headerLines.length) {
        requestBody = headerLines.slice(bodyStartIndex).join('\r\n');
      }
      
      return {
        id: randomUUID(),
        timestamp: new Date(timestamp).toISOString(),
        method,
        url,
        host: headers['Host'],
        headers,
        requestBody,
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
  // Check Authorization header (Basic Auth)
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
  
  // Check POST body for form data
  if (http.requestBody && http.method === 'POST') {
    const body = http.requestBody;
    
    // Common form field patterns for username/password
    const usernamePatterns = [
      /(?:username|user|uname|email|login)=([^&\r\n]+)/i,
      /(?:username|user|uname|email|login)%3D([^&\r\n]+)/i, // URL encoded =
    ];
    const passwordPatterns = [
      /(?:password|pass|passwd|pwd)=([^&\r\n]+)/i,
      /(?:password|pass|passwd|pwd)%3D([^&\r\n]+)/i, // URL encoded =
    ];
    
    let username = '';
    let password = '';
    
    // Try to find username
    for (const pattern of usernamePatterns) {
      const match = body.match(pattern);
      if (match) {
        username = decodeURIComponent(match[1]);
        break;
      }
    }
    
    // Try to find password
    for (const pattern of passwordPatterns) {
      const match = body.match(pattern);
      if (match) {
        password = decodeURIComponent(match[1]);
        break;
      }
    }
    
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
