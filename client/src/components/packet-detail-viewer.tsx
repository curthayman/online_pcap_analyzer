import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Copy, Check } from "lucide-react";
import type { Packet } from "@shared/schema";
import { Card } from "@/components/ui/card";

interface PacketDetailViewerProps {
  packet: Packet | null;
  onClose: () => void;
}

export function PacketDetailViewer({ packet, onClose }: PacketDetailViewerProps) {
  const [copied, setCopied] = useState(false);

  if (!packet) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Generate hex dump from packet data
  // Since we don't have raw payload, we'll create a mock hex view from packet info
  const generateHexDump = () => {
    // Create a simple hex representation
    const packetStr = JSON.stringify({
      protocol: packet.protocol,
      src: `${packet.sourceIP}:${packet.sourcePort || 'N/A'}`,
      dst: `${packet.destIP}:${packet.destPort || 'N/A'}`,
      len: packet.length,
      info: packet.info,
    });

    const bytes: number[] = [];
    for (let i = 0; i < packetStr.length; i++) {
      bytes.push(packetStr.charCodeAt(i));
    }

    const lines: string[] = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const offset = i.toString(16).padStart(4, '0');

      // Hex part
      const hexPart = chunk
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ')
        .padEnd(48, ' ');

      // ASCII part
      const asciiPart = chunk
        .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
        .join('');

      lines.push(`${offset}  ${hexPart}  ${asciiPart}`);
    }

    return lines.join('\n');
  };

  const hexDump = generateHexDump();

  return (
    <Dialog open={!!packet} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Packet Details</DialogTitle>
          <DialogDescription>
            Detailed information for packet at {packet.timestamp}
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="summary" className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="summary">Summary</TabsTrigger>
            <TabsTrigger value="hex">Hex Dump</TabsTrigger>
            <TabsTrigger value="raw">Raw Data</TabsTrigger>
          </TabsList>

          {/* Summary Tab */}
          <TabsContent value="summary" className="space-y-4 mt-4">
            <Card className="p-4">
              <h3 className="font-semibold mb-3">General Information</h3>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <span className="text-muted-foreground">Protocol:</span>
                  <span className="ml-2 font-medium">{packet.protocol}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Length:</span>
                  <span className="ml-2 font-medium">{packet.length} bytes</span>
                </div>
                <div className="col-span-2">
                  <span className="text-muted-foreground">Timestamp:</span>
                  <span className="ml-2 font-medium font-mono text-xs">
                    {packet.timestamp}
                  </span>
                </div>
              </div>
            </Card>

            <Card className="p-4">
              <h3 className="font-semibold mb-3">Network Layer</h3>
              <div className="space-y-3 text-sm">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <span className="text-muted-foreground">Source IP:</span>
                    <span className="ml-2 font-medium font-mono">
                      {packet.sourceIP}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Source Port:</span>
                    <span className="ml-2 font-medium">
                      {packet.sourcePort || 'N/A'}
                    </span>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <span className="text-muted-foreground">Destination IP:</span>
                    <span className="ml-2 font-medium font-mono">
                      {packet.destIP}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Destination Port:</span>
                    <span className="ml-2 font-medium">
                      {packet.destPort || 'N/A'}
                    </span>
                  </div>
                </div>
              </div>
            </Card>

            {packet.info && (
              <Card className="p-4">
                <h3 className="font-semibold mb-3">Additional Information</h3>
                <p className="text-sm text-muted-foreground">{packet.info}</p>
              </Card>
            )}
          </TabsContent>

          {/* Hex Dump Tab */}
          <TabsContent value="hex" className="space-y-4 mt-4">
            <div className="flex justify-between items-center">
              <p className="text-sm text-muted-foreground">
                Hexadecimal and ASCII representation
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleCopy(hexDump)}
              >
                {copied ? (
                  <>
                    <Check className="mr-2 h-4 w-4" />
                    Copied!
                  </>
                ) : (
                  <>
                    <Copy className="mr-2 h-4 w-4" />
                    Copy
                  </>
                )}
              </Button>
            </div>

            <Card className="p-4 bg-muted/50">
              <pre className="text-xs font-mono overflow-x-auto whitespace-pre">
                <code>{hexDump}</code>
              </pre>
            </Card>

            <div className="text-xs text-muted-foreground space-y-1">
              <p>• Each line shows 16 bytes</p>
              <p>• Left: Offset | Middle: Hexadecimal | Right: ASCII</p>
              <p>• Non-printable characters shown as "."</p>
            </div>
          </TabsContent>

          {/* Raw Data Tab */}
          <TabsContent value="raw" className="space-y-4 mt-4">
            <div className="flex justify-between items-center">
              <p className="text-sm text-muted-foreground">
                Complete packet data in JSON format
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleCopy(JSON.stringify(packet, null, 2))}
              >
                {copied ? (
                  <>
                    <Check className="mr-2 h-4 w-4" />
                    Copied!
                  </>
                ) : (
                  <>
                    <Copy className="mr-2 h-4 w-4" />
                    Copy JSON
                  </>
                )}
              </Button>
            </div>

            <Card className="p-4 bg-muted/50">
              <pre className="text-xs overflow-x-auto">
                <code>{JSON.stringify(packet, null, 2)}</code>
              </pre>
            </Card>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
