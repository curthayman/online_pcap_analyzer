import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity, Network, FileText, Shield, Video } from "lucide-react";
import type { PcapStatistics } from "@shared/schema";

interface StatisticsCardsProps {
  statistics: PcapStatistics;
  httpCount: number;
  dnsCount: number;
  filesCount: number;
  credentialsCount: number;
}

export function StatisticsCards({ 
  statistics, 
  httpCount, 
  dnsCount, 
  filesCount, 
  credentialsCount 
}: StatisticsCardsProps) {
  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  };

  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds.toFixed(1)}s`;
    const minutes = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${minutes}m ${secs}s`;
  };

  // Detect video call traffic (STUN = WebRTC indicator)
  const stunPackets = statistics.protocolDistribution['STUN'] || 0;
  const hasVideoCalls = stunPackets > 0;

  // Detect VPN traffic
  const vpnProtocols = ['ESP', 'IKE', 'OpenVPN', 'WireGuard', 'PPTP', 'GRE', 'L2TP'];
  const hasVpn = vpnProtocols.some(protocol => (statistics.protocolDistribution[protocol] || 0) > 0);

  const cards = hasVideoCalls ? [
    {
      title: "Total Packets",
      value: statistics.totalPackets.toLocaleString(),
      subtitle: formatBytes(statistics.totalBytes),
      icon: Activity,
      color: "text-chart-1",
    },
    {
      title: "Duration",
      value: formatDuration(statistics.duration),
      subtitle: `${Object.keys(statistics.protocolDistribution).length} protocols`,
      icon: Network,
      color: "text-chart-2",
    },
    {
      title: "Video Call Traffic",
      value: stunPackets.toLocaleString(),
      subtitle: "WebRTC STUN packets",
      icon: Video,
      color: "text-purple-500",
    },
    {
      title: "HTTP & Files",
      value: httpCount.toLocaleString(),
      subtitle: `${filesCount} files, ${credentialsCount} credentials`,
      icon: FileText,
      color: "text-protocol-http",
    },
  ] : [
    {
      title: "Total Packets",
      value: statistics.totalPackets.toLocaleString(),
      subtitle: formatBytes(statistics.totalBytes),
      icon: Activity,
      color: "text-chart-1",
    },
    {
      title: "Duration",
      value: formatDuration(statistics.duration),
      subtitle: `${Object.keys(statistics.protocolDistribution).length} protocols`,
      icon: Network,
      color: "text-chart-2",
    },
    {
      title: "HTTP Requests",
      value: httpCount.toLocaleString(),
      subtitle: `${dnsCount} DNS queries`,
      icon: FileText,
      color: "text-protocol-http",
    },
    {
      title: "Files & Credentials",
      value: filesCount.toLocaleString(),
      subtitle: `${credentialsCount} credentials found`,
      icon: Shield,
      color: "text-protocol-dns",
    },
  ];

  return (
    <div className="space-y-4">
      {/* VPN Indicator Badge */}
      <div className="flex items-center justify-end">
        <Badge 
          variant={hasVpn ? "default" : "secondary"}
          className={hasVpn ? "bg-green-600 hover:bg-green-700 text-white" : ""}
          data-testid="badge-vpn-status"
        >
          VPN {hasVpn ? "ON" : "OFF"}
        </Badge>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((card, index) => (
          <Card key={index} data-testid={`card-stat-${index}`}>
            <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                {card.title}
              </CardTitle>
              <card.icon className={`h-4 w-4 ${card.color}`} />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold" data-testid={`text-stat-value-${index}`}>
                {card.value}
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {card.subtitle}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
