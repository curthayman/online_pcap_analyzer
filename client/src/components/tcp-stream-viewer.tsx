import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Download, ArrowRight, ArrowLeft } from "lucide-react";
import type { TcpStream } from "@/lib/tcp-stream";
import { exportStreamAsText } from "@/lib/tcp-stream";
import { Badge } from "@/components/ui/badge";

interface TcpStreamViewerProps {
  stream: TcpStream | null;
  onClose: () => void;
}

export function TcpStreamViewer({ stream, onClose }: TcpStreamViewerProps) {
  if (!stream) return null;

  const formatBytes = (bytes: number) => {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;

    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }

    return `${size.toFixed(2)} ${units[unitIndex]}`;
  };

  const handleExport = () => {
    const text = exportStreamAsText(stream);
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tcp-stream-${stream.id}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const formatTime = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        fractionalSecondDigits: 3,
      });
    } catch {
      return timestamp;
    }
  };

  return (
    <Dialog open={!!stream} onOpenChange={onClose}>
      <DialogContent className="max-w-5xl max-h-[90vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>TCP Stream</DialogTitle>
          <DialogDescription>
            Complete conversation between {stream.clientIP}:{stream.clientPort} and{' '}
            {stream.serverIP}:{stream.serverPort}
          </DialogDescription>
        </DialogHeader>

        {/* Stream Summary */}
        <Card className="p-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">Packets</span>
              <p className="font-semibold">{stream.packets.length}</p>
            </div>
            <div>
              <span className="text-muted-foreground">Total Bytes</span>
              <p className="font-semibold">{formatBytes(stream.totalBytes)}</p>
            </div>
            <div>
              <span className="text-muted-foreground">Start Time</span>
              <p className="font-semibold font-mono text-xs">
                {formatTime(stream.startTime)}
              </p>
            </div>
            <div>
              <span className="text-muted-foreground">End Time</span>
              <p className="font-semibold font-mono text-xs">
                {formatTime(stream.endTime)}
              </p>
            </div>
          </div>
        </Card>

        {/* Stream Flow */}
        <div className="flex-1 overflow-y-auto space-y-2">
          {stream.packets.map((sp, index) => {
            const isClient = sp.direction === 'client';

            return (
              <div
                key={index}
                className={`flex items-start gap-3 ${
                  isClient ? 'flex-row' : 'flex-row-reverse'
                }`}
              >
                {/* Direction Indicator */}
                <div className="flex-shrink-0 pt-3">
                  {isClient ? (
                    <ArrowRight className="h-5 w-5 text-blue-500" />
                  ) : (
                    <ArrowLeft className="h-5 w-5 text-green-500" />
                  )}
                </div>

                {/* Packet Card */}
                <Card
                  className={`flex-1 p-3 ${
                    isClient
                      ? 'bg-blue-50 dark:bg-blue-950/30 border-blue-200 dark:border-blue-900'
                      : 'bg-green-50 dark:bg-green-950/30 border-green-200 dark:border-green-900'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={isClient ? 'default' : 'secondary'}
                        className={
                          isClient
                            ? 'bg-blue-600 hover:bg-blue-700'
                            : 'bg-green-600 hover:bg-green-700'
                        }
                      >
                        {isClient ? 'CLIENT' : 'SERVER'}
                      </Badge>
                      <span className="text-xs text-muted-foreground">
                        Packet #{index + 1}
                      </span>
                    </div>
                    <span className="text-xs font-mono text-muted-foreground">
                      {formatTime(sp.packet.timestamp)}
                    </span>
                  </div>

                  <div className="space-y-1 text-sm">
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground">From:</span>
                      <span className="font-mono text-xs">
                        {sp.packet.sourceIP}:{sp.packet.sourcePort || 'N/A'}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground">To:</span>
                      <span className="font-mono text-xs">
                        {sp.packet.destIP}:{sp.packet.destPort || 'N/A'}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground">Length:</span>
                      <span className="font-medium">{sp.packet.length} bytes</span>
                    </div>
                    {sp.packet.info && (
                      <div className="mt-2 pt-2 border-t">
                        <p className="text-xs text-muted-foreground">
                          {sp.packet.info}
                        </p>
                      </div>
                    )}
                  </div>
                </Card>
              </div>
            );
          })}
        </div>

        {/* Export Button */}
        <div className="flex justify-end pt-4 border-t">
          <Button onClick={handleExport}>
            <Download className="mr-2 h-4 w-4" />
            Export Stream as Text
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
