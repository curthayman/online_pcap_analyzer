import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { ChevronRight } from "lucide-react";
import type { HttpTransaction } from "@shared/schema";
import { ProtocolBadge } from "./protocol-badge";

interface HttpTableProps {
  transactions: HttpTransaction[];
  onRowClick?: (transaction: HttpTransaction) => void;
}

export function HttpTable({ transactions, onRowClick }: HttpTableProps) {
  const getStatusColor = (status?: number) => {
    if (!status) return "bg-muted text-muted-foreground";
    if (status >= 200 && status < 300) return "bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/20";
    if (status >= 300 && status < 400) return "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20";
    if (status >= 400 && status < 500) return "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20";
    return "bg-destructive/10 text-destructive border-destructive/20";
  };

  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  if (transactions.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <p>No HTTP transactions found</p>
      </div>
    );
  }

  return (
    <div className="border rounded-md">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[100px]">Time</TableHead>
            <TableHead>Method</TableHead>
            <TableHead>URL</TableHead>
            <TableHead>Source IP</TableHead>
            <TableHead>Dest IP</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="w-[50px]"></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {transactions.map((transaction) => (
            <TableRow
              key={transaction.id}
              onClick={() => onRowClick?.(transaction)}
              className={onRowClick ? "cursor-pointer hover-elevate" : ""}
              data-testid={`row-http-${transaction.id}`}
            >
              <TableCell className="font-mono text-xs text-muted-foreground">
                {formatTime(transaction.timestamp)}
              </TableCell>
              <TableCell>
                <ProtocolBadge protocol={transaction.method} />
              </TableCell>
              <TableCell className="font-mono text-sm max-w-md truncate">
                {transaction.url}
              </TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">
                {transaction.sourceIP}
              </TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">
                {transaction.destIP}
              </TableCell>
              <TableCell>
                {transaction.statusCode && (
                  <Badge variant="outline" className={`border ${getStatusColor(transaction.statusCode)}`}>
                    {transaction.statusCode}
                  </Badge>
                )}
              </TableCell>
              <TableCell>
                {onRowClick && <ChevronRight className="h-4 w-4 text-muted-foreground" />}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
