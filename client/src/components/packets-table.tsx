import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { Packet } from "@shared/schema";
import { ProtocolBadge } from "./protocol-badge";

interface PacketsTableProps {
  packets: Packet[];
}

export function PacketsTable({ packets }: PacketsTableProps) {
  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString();
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
            <TableRow key={packet.id} data-testid={`row-packet-${packet.id}`}>
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
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
