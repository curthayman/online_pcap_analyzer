import { z } from "zod";

// PCAP Analysis Schema
export const pcapAnalysisSchema = z.object({
  id: z.string(),
  fileName: z.string(),
  fileSize: z.number(),
  uploadedAt: z.string(),
  status: z.enum(['analyzing', 'completed', 'error']),
  totalPackets: z.number(),
  duration: z.number().optional(),
  protocols: z.array(z.string()),
});

export type PcapAnalysis = z.infer<typeof pcapAnalysisSchema>;

// Network Node Schema
export const networkNodeSchema = z.object({
  id: z.string(),
  ipAddress: z.string(),
  macAddress: z.string().optional(),
  hostname: z.string().optional(),
  nodeType: z.enum(['router', 'server', 'client', 'unknown']),
  packetCount: z.number(),
  protocols: z.array(z.string()),
});

export type NetworkNode = z.infer<typeof networkNodeSchema>;

// Network Connection Schema
export const networkConnectionSchema = z.object({
  id: z.string(),
  sourceIP: z.string(),
  destIP: z.string(),
  protocol: z.string(),
  packetCount: z.number(),
  bytes: z.number(),
});

export type NetworkConnection = z.infer<typeof networkConnectionSchema>;

// HTTP Transaction Schema
export const httpTransactionSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  method: z.string(),
  url: z.string(),
  host: z.string().optional(),
  headers: z.record(z.string()),
  statusCode: z.number().optional(),
  responseHeaders: z.record(z.string()).optional(),
  sourceIP: z.string(),
  destIP: z.string(),
  requestBody: z.string().optional(),
  responseBody: z.string().optional(),
});

export type HttpTransaction = z.infer<typeof httpTransactionSchema>;

// DNS Query Schema
export const dnsQuerySchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  queryType: z.string(),
  domain: z.string(),
  response: z.array(z.string()),
  sourceIP: z.string(),
  destIP: z.string(),
  ttl: z.number().optional(),
});

export type DnsQuery = z.infer<typeof dnsQuerySchema>;

// Extracted File Schema
export const extractedFileSchema = z.object({
  id: z.string(),
  fileName: z.string(),
  fileType: z.string(),
  fileSize: z.number(),
  protocol: z.string(),
  sourceIP: z.string(),
  destIP: z.string(),
  timestamp: z.string(),
  data: z.string(), // base64 encoded
  mimeType: z.string().optional(),
});

export type ExtractedFile = z.infer<typeof extractedFileSchema>;

// Credential Schema
export const credentialSchema = z.object({
  id: z.string(),
  protocol: z.string(),
  username: z.string(),
  password: z.string(),
  type: z.enum(['plaintext', 'hash']),
  timestamp: z.string(),
  sourceIP: z.string(),
  destIP: z.string().optional(),
});

export type Credential = z.infer<typeof credentialSchema>;

// Packet Schema
export const packetSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  protocol: z.string(),
  sourceIP: z.string(),
  destIP: z.string(),
  sourcePort: z.number().optional(),
  destPort: z.number().optional(),
  length: z.number(),
  info: z.string().optional(),
});

export type Packet = z.infer<typeof packetSchema>;

// Statistics Schema
export const pcapStatisticsSchema = z.object({
  totalPackets: z.number(),
  totalBytes: z.number(),
  duration: z.number(),
  protocolDistribution: z.record(z.number()),
  topTalkers: z.array(z.object({
    ip: z.string(),
    packets: z.number(),
    bytes: z.number(),
  })),
  timelineData: z.array(z.object({
    timestamp: z.string(),
    packets: z.number(),
  })),
});

export type PcapStatistics = z.infer<typeof pcapStatisticsSchema>;

// Complete Analysis Result Schema
export const analysisResultSchema = z.object({
  analysis: pcapAnalysisSchema,
  statistics: pcapStatisticsSchema,
  nodes: z.array(networkNodeSchema),
  connections: z.array(networkConnectionSchema),
  httpTransactions: z.array(httpTransactionSchema),
  dnsQueries: z.array(dnsQuerySchema),
  extractedFiles: z.array(extractedFileSchema),
  credentials: z.array(credentialSchema),
  packets: z.array(packetSchema),
});

export type AnalysisResult = z.infer<typeof analysisResultSchema>;
