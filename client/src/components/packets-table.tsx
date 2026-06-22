import { useState } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import type { Packet } from "@shared/schema";
import { ProtocolBadge } from "./protocol-badge";
import { Network, FileText } from "lucide-react";

interface PacketsTableProps {
  packets: Packet[];
  onPacketClick?: (packet: Packet) => void;
  onFollowStream?: (packet: Packet) => void;
}

export function PacketsTable({ packets, onPacketClick, onFollowStream }: PacketsTableProps) {
  const [selectedPacket, setSelectedPacket] = useState<string | null>(null);

  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const handleRowClick = (packet: Packet) => {
    setSelectedPacket(packet.id);
    onPacketClick?.(packet);
  };

  const handleFollowStream = (packet: Packet) => {
    if (packet.protocol === 'TCP' && packet.sourcePort && packet.destPort) {
      onFollowStream?.(packet);
    }
  };

  const canFollowStream = (packet: Packet) => {
    return packet.protocol === 'TCP' && packet.sourcePort && packet.destPort;
  };

  if (packets.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <p>No packets available</p>
      </div>
    );
  }

  return (
    <div className="border rounded-md">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[100px]">Time</TableHead>
            <TableHead>Protocol</TableHead>
            <TableHead>Source</TableHead>
            <TableHead>Destination</TableHead>
            <TableHead>Length</TableHead>
            <TableHead>Info</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {packets.map((packet) => (
            <ContextMenu key={packet.id}>
              <ContextMenuTrigger asChild>
                <TableRow
                  data-testid={`row-packet-${packet.id}`}
                  className={`cursor-pointer hover:bg-muted/50 ${
                    selectedPacket === packet.id ? 'bg-muted' : ''
                  }`}
                  onClick={() => handleRowClick(packet)}
                >
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {formatTime(packet.timestamp)}
                  </TableCell>
                  <TableCell>
                    <ProtocolBadge protocol={packet.protocol} />
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    <div className="flex flex-col">
                      <span>{packet.sourceIP}</span>
                      {packet.sourcePort && (
                        <span className="text-[10px]">:{packet.sourcePort}</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    <div className="flex flex-col">
                      <span>{packet.destIP}</span>
                      {packet.destPort && (
                        <span className="text-[10px]">:{packet.destPort}</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {packet.length} bytes
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground truncate max-w-md">
                    {packet.info || '-'}
                  </TableCell>
                </TableRow>
              </ContextMenuTrigger>
              <ContextMenuContent>
                <ContextMenuItem onClick={() => handleRowClick(packet)}>
                  <FileText className="mr-2 h-4 w-4" />
                  View Packet Details
                </ContextMenuItem>
                {canFollowStream(packet) && (
                  <ContextMenuItem onClick={() => handleFollowStream(packet)}>
                    <Network className="mr-2 h-4 w-4" />
                    Follow TCP Stream
                  </ContextMenuItem>
                )}
              </ContextMenuContent>
            </ContextMenu>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
