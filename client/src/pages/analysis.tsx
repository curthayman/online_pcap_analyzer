import { useParams, useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Download, Network as NetworkIcon } from "lucide-react";
import { StatisticsCards } from "@/components/statistics-cards";
import { NetworkGraph } from "@/components/network-graph";
import { HttpTable } from "@/components/http-table";
import { DnsTable } from "@/components/dns-table";
import { FilesTable } from "@/components/files-table";
import { CredentialsTable } from "@/components/credentials-table";
import { PacketsTable } from "@/components/packets-table";
import { WiFiTable } from "@/components/wifi-table";
import type { AnalysisResult } from "@shared/schema";

export default function Analysis() {
  const { id } = useParams();
  const [, setLocation] = useLocation();

  const { data: result, isLoading, error } = useQuery<AnalysisResult>({
    queryKey: ['/api/analysis', id],
    enabled: !!id,
  });

  const handleDownloadReport = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `analysis-${result.analysis.fileName}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 rounded-full border-4 border-primary border-t-transparent animate-spin" />
          <p className="text-muted-foreground">Loading analysis...</p>
        </div>
      </div>
    );
  }

  if (error || !result) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center space-y-4">
          <p className="text-destructive">Failed to load analysis</p>
          <Button onClick={() => setLocation('/')} data-testid="button-back-error">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Home
          </Button>
        </div>
      </div>
    );
  }

  const hasWiFi = result.wifiNetworks && result.wifiNetworks.length > 0;
  const tabCount = hasWiFi ? 7 : 6;

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b sticky top-0 bg-background/80 backdrop-blur-sm z-50">
        <div className="container mx-auto px-6 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setLocation('/')}
              data-testid="button-back"
            >
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
            <div className="flex items-center gap-2">
              <NetworkIcon className="h-5 w-5 text-primary" />
              <div className="flex flex-col">
                <h1 className="text-sm font-semibold truncate max-w-[200px] md:max-w-md">
                  {result.analysis.fileName}
                </h1>
                <p className="text-xs text-muted-foreground">
                  {(result.analysis.fileSize / 1024).toFixed(2)} KB
                </p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleDownloadReport}
              data-testid="button-download-report"
            >
              <Download className="mr-2 h-4 w-4" />
              <span className="hidden md:inline">Download Report</span>
            </Button>
            <ThemeToggle />
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8">
        <div className="space-y-8">
          {/* Statistics */}
          <StatisticsCards
            statistics={result.statistics}
            httpCount={result.httpTransactions.length}
            dnsCount={result.dnsQueries.length}
            filesCount={result.extractedFiles.length}
            credentialsCount={result.credentials.length}
          />

          {/* Tabs */}
          <Tabs defaultValue="overview" className="w-full">
            <TabsList className={`grid w-full grid-cols-3 lg:grid-cols-${tabCount} gap-1 h-auto p-1 bg-muted/50`}>
              <TabsTrigger value="overview" data-testid="tab-overview" className="data-[state=inactive]:text-foreground/80">Overview</TabsTrigger>
              <TabsTrigger value="http" data-testid="tab-http" className="data-[state=inactive]:text-foreground/80">HTTP</TabsTrigger>
              <TabsTrigger value="dns" data-testid="tab-dns" className="data-[state=inactive]:text-foreground/80">DNS</TabsTrigger>
              {hasWiFi && (
                <TabsTrigger value="wifi" data-testid="tab-wifi" className="data-[state=inactive]:text-foreground/80">WiFi</TabsTrigger>
              )}
              <TabsTrigger value="files" data-testid="tab-files" className="data-[state=inactive]:text-foreground/80">Files</TabsTrigger>
              <TabsTrigger value="credentials" data-testid="tab-credentials" className="data-[state=inactive]:text-foreground/80">Credentials</TabsTrigger>
              <TabsTrigger value="packets" data-testid="tab-packets" className="data-[state=inactive]:text-foreground/80">Packets</TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="space-y-6 mt-6">
              <div>
                <h2 className="text-2xl font-semibold mb-4">Network Topology</h2>
                <NetworkGraph
                  nodes={result.nodes}
                  connections={result.connections}
                />
              </div>

              <div>
                <h2 className="text-2xl font-semibold mb-4">Protocol Distribution</h2>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {Object.entries(result.statistics.protocolDistribution).map(([protocol, count]) => (
                    <div
                      key={protocol}
                      className="border rounded-md p-4 bg-card"
                      data-testid={`protocol-stat-${protocol.toLowerCase()}`}
                    >
                      <p className="text-sm text-muted-foreground">{protocol}</p>
                      <p className="text-2xl font-bold">{count.toLocaleString()}</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {((count / result.statistics.totalPackets) * 100).toFixed(1)}%
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="http" className="mt-6">
              <div className="space-y-4">
                <div>
                  <h2 className="text-2xl font-semibold">HTTP Transactions</h2>
                  <p className="text-sm text-muted-foreground">
                    {result.httpTransactions.length} HTTP requests and responses
                  </p>
                </div>
                <HttpTable transactions={result.httpTransactions} />
              </div>
            </TabsContent>

            <TabsContent value="dns" className="mt-6">
              <div className="space-y-4">
                <div>
                  <h2 className="text-2xl font-semibold">DNS Queries</h2>
                  <p className="text-sm text-muted-foreground">
                    {result.dnsQueries.length} DNS queries and responses
                  </p>
                </div>
                <DnsTable queries={result.dnsQueries} />
              </div>
            </TabsContent>

            {hasWiFi && (
              <TabsContent value="wifi" className="mt-6">
                <div className="space-y-4">
                  <div>
                    <h2 className="text-2xl font-semibold">WiFi Networks</h2>
                    <p className="text-sm text-muted-foreground">
                      {result.wifiNetworks?.length || 0} wireless networks detected
                    </p>
                  </div>
                  <WiFiTable networks={result.wifiNetworks || []} />
                </div>
              </TabsContent>
            )}

            <TabsContent value="files" className="mt-6">
              <div className="space-y-4">
                <div>
                  <h2 className="text-2xl font-semibold">Extracted Files</h2>
                  <p className="text-sm text-muted-foreground">
                    {result.extractedFiles.length} files extracted from network traffic
                  </p>
                </div>
                <FilesTable files={result.extractedFiles} />
              </div>
            </TabsContent>

            <TabsContent value="credentials" className="mt-6">
              <div className="space-y-4">
                <div>
                  <h2 className="text-2xl font-semibold">Discovered Credentials</h2>
                  <p className="text-sm text-muted-foreground">
                    {result.credentials.length} credentials found in plaintext protocols
                  </p>
                </div>
                <CredentialsTable credentials={result.credentials} />
              </div>
            </TabsContent>

            <TabsContent value="packets" className="mt-6">
              <div className="space-y-4">
                <div>
                  <h2 className="text-2xl font-semibold">All Packets</h2>
                  <p className="text-sm text-muted-foreground">
                    {result.packets.length} packets captured
                  </p>
                </div>
                <PacketsTable packets={result.packets.slice(0, 100)} />
                {result.packets.length > 100 && (
                  <p className="text-sm text-muted-foreground text-center py-4">
                    Showing first 100 packets of {result.packets.length} total
                  </p>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </main>
    </div>
  );
}
