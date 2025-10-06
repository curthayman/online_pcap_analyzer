import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Eye, EyeOff, Copy, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import type { Credential } from "@shared/schema";
import { ProtocolBadge } from "./protocol-badge";

interface CredentialsTableProps {
  credentials: Credential[];
}

export function CredentialsTable({ credentials }: CredentialsTableProps) {
  const [visiblePasswords, setVisiblePasswords] = useState<Set<string>>(new Set());
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const togglePasswordVisibility = (id: string) => {
    setVisiblePasswords(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  if (credentials.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <p>No credentials found</p>
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
            <TableHead>Username</TableHead>
            <TableHead>Password</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Source IP</TableHead>
            <TableHead className="w-[100px]">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {credentials.map((cred) => {
            const isVisible = visiblePasswords.has(cred.id);
            const isCopied = copiedId === cred.id;
            
            return (
              <TableRow key={cred.id} data-testid={`row-credential-${cred.id}`}>
                <TableCell className="font-mono text-xs text-muted-foreground">
                  {formatTime(cred.timestamp)}
                </TableCell>
                <TableCell>
                  <ProtocolBadge protocol={cred.protocol} />
                </TableCell>
                <TableCell className="font-mono text-sm">
                  {cred.username}
                </TableCell>
                <TableCell className="font-mono text-sm">
                  {isVisible ? cred.password : '••••••••'}
                </TableCell>
                <TableCell>
                  <Badge 
                    variant="outline"
                    className={cred.type === 'plaintext' 
                      ? "border-amber-500/20 bg-amber-500/10 text-amber-600 dark:text-amber-400"
                      : "border-muted bg-muted/50 text-muted-foreground"
                    }
                  >
                    {cred.type}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">
                  {cred.sourceIP}
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => togglePasswordVisibility(cred.id)}
                      data-testid={`button-toggle-password-${cred.id}`}
                    >
                      {isVisible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => copyToClipboard(cred.password, cred.id)}
                      data-testid={`button-copy-${cred.id}`}
                    >
                      {isCopied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
