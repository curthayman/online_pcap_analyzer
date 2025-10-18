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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { WiFiNetwork } from "@shared/schema";
import { Signal, Lock, Unlock, Users } from "lucide-react";

interface WiFiTableProps {
  networks: WiFiNetwork[];
}

// Simple MAC OUI vendor lookup (common manufacturers)
function getMacVendor(mac: string): string {
  const oui = mac.substring(0, 8).toUpperCase().replace(/:/g, '');
  
  const vendors: Record<string, string> = {
    '00001C': 'Apple',
    '00003E': 'Apple',
    '000502': 'Apple',
    '000A27': 'Apple',
    '000A95': 'Apple',
    '000D93': 'Apple',
    '001124': 'Apple',
    '001451': 'Apple',
    '0016CB': 'Apple',
    '0017F2': 'Apple',
    '001CB3': 'Apple',
    '001EC2': 'Apple',
    '001F5B': 'Apple',
    '001FF3': 'Apple',
    '0021E9': 'Apple',
    '002241': 'Apple',
    '002312': 'Apple',
    '002332': 'Apple',
    '002436': 'Apple',
    '00254B': 'Apple',
    '002556': 'Apple',
    '002608': 'Apple',
    '00264A': 'Apple',
    '28CFE9': 'Apple',
    '3C0754': 'Apple',
    '3CE072': 'Apple',
    '40B395': 'Apple',
    '5C95AE': 'Apple',
    '7081EB': 'Apple',
    '7C0191': 'Apple',
    '7C6D62': 'Apple',
    '7CF05F': 'Apple',
    '8863DF': 'Apple',
    '8C2937': 'Apple',
    'A46CF1': 'Apple',
    'A4B197': 'Apple',
    'A85B78': 'Apple',
    'B065BD': 'Apple',
    'B88D12': 'Apple',
    'C82A14': 'Apple',
    'D023DB': 'Apple',
    'D8004D': 'Apple',
    'D89695': 'Apple',
    'DC2B2A': 'Apple',
    'E0ACCB': 'Apple',
    'F0B479': 'Apple',
    'F0DBE2': 'Apple',
    '000C29': 'VMware',
    '005056': 'VMware',
    '000569': 'VMware',
    '001C14': 'VMware',
    '0050F2': 'Microsoft',
    '001DD8': 'Microsoft',
    '0019D1': 'Microsoft',
    '7C1E52': 'Microsoft',
    '000D3A': 'Microsoft',
    '001377': 'Intel',
    '001999': 'Intel',
    '001E64': 'Intel',
    '001E65': 'Intel',
    '001F3A': 'Intel',
    '0022FA': 'Intel',
    '002481': 'Intel',
    '0024D6': 'Intel',
    '0024D7': 'Intel',
    '0025BC': 'Intel',
    '002655': 'Intel',
    '0027EB': 'Intel',
    '00D0B7': 'Intel',
    '001B63': 'Samsung',
    '002566': 'Samsung',
    '0026FC': 'Samsung',
    '0027F8': 'Samsung',
    '0C8268': 'Samsung',
    '14109F': 'Samsung',
    '1C232C': 'Samsung',
    '1C5A3E': 'Samsung',
    '2C27D7': 'Samsung',
    '341276': 'Samsung',
    '34BE00': 'Samsung',
    '38AA3C': 'Samsung',
    '3C7709': 'Samsung',
    '5C0A5B': 'Samsung',
    '68A86D': 'Samsung',
    'C06599': 'Samsung',
    'CC07AB': 'Samsung',
    'E8039A': 'Samsung',
    'EC1D8B': 'Samsung',
    'B4F61C': 'Google',
    '54EAA8': 'Google',
    '3C5AB4': 'Google',
    'F4F5E8': 'Google',
    '9C65F9': 'Google',
    '000F86': 'Cisco',
    '001562': 'Cisco',
    '0019AA': 'Cisco',
    '001E14': 'Cisco',
    '00214D': 'Cisco',
    '002264': 'Cisco',
    '00E04C': 'Realtek',
    'B0E892': 'Realtek',
    'E0469A': 'Realtek',
    '001A11': 'Google/Nest',
    '18B430': 'Google/Nest',
  };
  
  return vendors[oui] || 'Unknown';
}

export function WiFiTable({ networks }: WiFiTableProps) {
  const [selectedNetwork, setSelectedNetwork] = useState<WiFiNetwork | null>(null);
  const [isDialogOpen, setIsDialogOpen] = useState(false);

  const getSignalIcon = (strength?: number) => {
    if (!strength) return null;
    const absStrength = Math.abs(strength);
    if (absStrength >= 70) return <Signal className="h-4 w-4 text-red-500" />;
    if (absStrength >= 50) return <Signal className="h-4 w-4 text-orange-500" />;
    return <Signal className="h-4 w-4 text-green-500" />;
  };

  const handleClientClick = (network: WiFiNetwork) => {
    setSelectedNetwork(network);
    setIsDialogOpen(true);
  };

  if (networks.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <p>No WiFi networks found</p>
      </div>
    );
  }

  return (
    <>
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
                  {network.clientMACs.length > 0 ? (
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => handleClientClick(network)}
                      data-testid={`button-clients-${network.id}`}
                      className="h-7 px-3"
                    >
                      <Users className="h-3 w-3 mr-1" />
                      {network.clientMACs.length} {network.clientMACs.length === 1 ? 'client' : 'clients'}
                    </Button>
                  ) : (
                    <Badge variant="secondary">0 clients</Badge>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Clients Dialog */}
      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-hidden flex flex-col">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Users className="h-5 w-5 text-protocol-wifi" />
              Connected Clients - {selectedNetwork?.ssid}
            </DialogTitle>
            <DialogDescription>
              {selectedNetwork?.clientMACs.length} device(s) connected to this network
            </DialogDescription>
          </DialogHeader>
          <div className="flex-1 overflow-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[50px]">#</TableHead>
                  <TableHead>MAC Address</TableHead>
                  <TableHead>Vendor</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {selectedNetwork?.clientMACs.map((mac, index) => (
                  <TableRow key={mac} data-testid={`row-client-${index}`}>
                    <TableCell className="text-muted-foreground">{index + 1}</TableCell>
                    <TableCell className="font-mono text-sm" data-testid={`text-client-mac-${index}`}>
                      {mac}
                    </TableCell>
                    <TableCell data-testid={`text-client-vendor-${index}`}>
                      <Badge variant="outline">{getMacVendor(mac)}</Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
