import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface ProtocolBadgeProps {
  protocol: string;
  className?: string;
}

const protocolColors: Record<string, string> = {
  HTTP: "bg-protocol-http/10 text-protocol-http border-protocol-http/20",
  HTTPS: "bg-protocol-http/10 text-protocol-http border-protocol-http/20",
  DNS: "bg-protocol-dns/10 text-protocol-dns border-protocol-dns/20",
  TCP: "bg-protocol-tcp/10 text-protocol-tcp border-protocol-tcp/20",
  UDP: "bg-protocol-udp/10 text-protocol-udp border-protocol-udp/20",
  ARP: "bg-protocol-arp/10 text-protocol-arp border-protocol-arp/20",
  ICMP: "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20",
  SSH: "bg-protocol-ssl/10 text-protocol-ssl border-protocol-ssl/20",
  FTP: "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20",
  TELNET: "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20",
  SMB: "bg-protocol-smb/10 text-protocol-smb border-protocol-smb/20",
};

export function ProtocolBadge({ protocol, className }: ProtocolBadgeProps) {
  const upperProtocol = protocol.toUpperCase();
  const colorClass = protocolColors[upperProtocol] || "bg-muted text-muted-foreground";

  return (
    <Badge 
      variant="outline" 
      className={cn("font-mono text-xs border", colorClass, className)}
      data-testid={`badge-protocol-${protocol.toLowerCase()}`}
    >
      {upperProtocol}
    </Badge>
  );
}
