import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import type { DnsQuery } from "@shared/schema";
import { ProtocolBadge } from "./protocol-badge";

interface DnsTableProps {
  queries: DnsQuery[];
}

export function DnsTable({ queries }: DnsTableProps) {
  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  if (queries.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <p>No DNS queries found</p>
      </div>
    );
  }

  return (
    <div className="border rounded-md">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[100px]">Time</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Domain</TableHead>
            <TableHead>Response</TableHead>
            <TableHead>Source IP</TableHead>
            <TableHead>DNS Server</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {queries.map((query) => (
            <TableRow key={query.id} data-testid={`row-dns-${query.id}`}>
              <TableCell className="font-mono text-xs text-muted-foreground">
                {formatTime(query.timestamp)}
              </TableCell>
              <TableCell>
                <ProtocolBadge protocol={query.queryType} />
              </TableCell>
              <TableCell className="font-mono text-sm">
                {query.domain}
              </TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground max-w-xs truncate">
                {query.response.join(', ') || 'No response'}
              </TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">
                {query.sourceIP}
              </TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">
                {query.destIP}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
