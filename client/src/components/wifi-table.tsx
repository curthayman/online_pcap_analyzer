import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import type { WiFiNetwork } from "@shared/schema";
import { Signal, Lock, Unlock } from "lucide-react";

interface WiFiTableProps {
  networks: WiFiNetwork[];
}

export function WiFiTable({ networks }: WiFiTableProps) {
  const getSignalIcon = (strength?: number) => {
    if (!strength) return null;
    const absStrength = Math.abs(strength);
    if (absStrength >= 70) return <Signal className="h-4 w-4 text-red-500" />;
    if (absStrength >= 50) return <Signal className="h-4 w-4 text-orange-500" />;
    return <Signal className="h-4 w-4 text-green-500" />;
  };

  if (networks.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <p>No WiFi networks found</p>
      </div>
    );
  }

  return (
    <div className="border rounded-md">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>SSID</TableHead>
            <TableHead>BSSID</TableHead>
            <TableHead className="w-[100px]">Channel</TableHead>
            <TableHead className="w-[100px]">Encryption</TableHead>
            <TableHead className="w-[120px]">Signal</TableHead>
            <TableHead className="w-[100px]">Beacons</TableHead>
            <TableHead className="w-[100px]">Data Frames</TableHead>
            <TableHead>Clients</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {networks.map((network) => (
            <TableRow key={network.id} data-testid={`row-wifi-${network.id}`}>
              <TableCell className="font-semibold" data-testid={`text-ssid-${network.id}`}>
                {network.ssid}
              </TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground" data-testid={`text-bssid-${network.id}`}>
                {network.bssid}
              </TableCell>
              <TableCell className="text-center" data-testid={`text-channel-${network.id}`}>
                {network.channel ? (
                  <Badge variant="outline">{network.channel}</Badge>
                ) : (
                  <span className="text-muted-foreground">-</span>
                )}
              </TableCell>
              <TableCell data-testid={`text-encryption-${network.id}`}>
                <div className="flex items-center gap-2">
                  {network.encryption === 'Encrypted' ? (
                    <>
                      <Lock className="h-3 w-3 text-green-600" />
                      <span className="text-xs">Encrypted</span>
                    </>
                  ) : (
                    <>
                      <Unlock className="h-3 w-3 text-orange-600" />
                      <span className="text-xs">Open</span>
                    </>
                  )}
                </div>
              </TableCell>
              <TableCell data-testid={`text-signal-${network.id}`}>
                <div className="flex items-center gap-2">
                  {getSignalIcon(network.signalStrength)}
                  <span className="font-mono text-xs">
                    {network.signalStrength ? `${network.signalStrength} dBm` : '-'}
                  </span>
                </div>
              </TableCell>
              <TableCell className="text-center" data-testid={`text-beacons-${network.id}`}>
                {network.beaconCount.toLocaleString()}
              </TableCell>
              <TableCell className="text-center" data-testid={`text-dataframes-${network.id}`}>
                {network.dataFrameCount.toLocaleString()}
              </TableCell>
              <TableCell data-testid={`text-clients-${network.id}`}>
                <Badge variant="secondary">
                  {network.clientMACs.length} {network.clientMACs.length === 1 ? 'client' : 'clients'}
                </Badge>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
