import { Card } from "@/components/ui/card";
import { Shield, AlertTriangle, Info, AlertCircle, Lock } from "lucide-react";
import type { AnalysisResult } from "@shared/schema";

interface ExecutiveSummaryProps {
  result: AnalysisResult;
}

export function ExecutiveSummary({ result }: ExecutiveSummaryProps) {
  const { analysis, statistics } = result;

  // Get top protocol
  const protocols = Object.entries(statistics.protocolDistribution);
  const topProtocol = protocols.sort((a, b) => b[1] - a[1])[0];

  // Calculate security findings by severity
  const findings = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  if (result.securityFindings) {
    result.securityFindings.forEach((finding) => {
      const severity = finding.severity?.toLowerCase() || 'info';
      if (severity in findings) {
        findings[severity as keyof typeof findings]++;
      }
    });
  }

  const totalFindings = Object.values(findings).reduce((a, b) => a + b, 0);

  const formatBytes = (bytes: number) => {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;

    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }

    return `${size.toFixed(2)} ${units[unitIndex]}`;
  };

  const vpn = analysis.vpnDetection;

  return (
    <Card className="p-6 bg-gradient-to-br from-primary/5 to-chart-1/5 border-primary/20">
      {vpn?.detected && (
        <div className={`mb-5 flex gap-3 rounded-lg border p-4 ${
          vpn.confidence === 'high'
            ? 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400'
            : 'border-yellow-500/40 bg-yellow-500/10 text-yellow-700 dark:text-yellow-400'
        }`}>
          <Lock className="mt-0.5 h-5 w-5 shrink-0" />
          <div className="space-y-1">
            <p className="font-semibold text-sm">
              VPN activity detected — capture likely recorded behind a VPN
            </p>
            <p className="text-xs opacity-80">
              {vpn.vpnType && <span className="font-medium">{vpn.vpnType}</span>}
              {vpn.tunnelEndpoint && <span> · tunnel endpoint: {vpn.tunnelEndpoint}</span>}
              {' · '}confidence: {vpn.confidence}
            </p>
            <ul className="text-xs opacity-75 space-y-0.5 mt-1">
              {vpn.indicators.map((ind, i) => (
                <li key={i} className="flex items-start gap-1">
                  <span className="mt-0.5">·</span>
                  <span>{ind}</span>
                </li>
              ))}
            </ul>
            <p className="text-xs opacity-60 mt-1">
              Traffic analysis may show the VPN server as the primary destination rather than actual sites visited. Payload content is encrypted and not inspectable.
            </p>
          </div>
        </div>
      )}

      <div className="flex items-start justify-between mb-4">
        <div>
          <h2 className="text-2xl font-bold mb-1">Executive Summary</h2>
          <p className="text-sm text-muted-foreground">
            High-level overview of network capture analysis
          </p>
        </div>
        <Shield className="h-8 w-8 text-primary opacity-50" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mt-6">
        {/* Capture Info */}
        <div className="space-y-2">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Capture
          </p>
          <p className="text-sm">
            <span className="font-medium">File:</span> {analysis.fileName}
          </p>
          <p className="text-sm">
            <span className="font-medium">Packets:</span>{' '}
            {analysis.totalPackets.toLocaleString()}
          </p>
          <p className="text-sm">
            <span className="font-medium">Duration:</span>{' '}
            {(analysis.duration ?? 0).toFixed(2)}s
          </p>
        </div>

        {/* Data Volume */}
        <div className="space-y-2">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Data Volume
          </p>
          <p className="text-sm">
            <span className="font-medium">Total:</span>{' '}
            {formatBytes(statistics.totalBytes)}
          </p>
          <p className="text-sm">
            <span className="font-medium">Top Protocol:</span>{' '}
            {topProtocol ? `${topProtocol[0]} (${topProtocol[1].toLocaleString()})` : 'N/A'}
          </p>
          <p className="text-sm">
            <span className="font-medium">Protocols:</span> {analysis.protocols.length}
          </p>
        </div>

        {/* Security Status */}
        <div className="space-y-2">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Security Status
          </p>
          {totalFindings > 0 ? (
            <div className="space-y-1">
              {findings.critical > 0 && (
                <div className="flex items-center gap-2 text-sm">
                  <AlertCircle className="h-4 w-4 text-red-600" />
                  <span className="font-semibold text-red-600">
                    {findings.critical} Critical
                  </span>
                </div>
              )}
              {findings.high > 0 && (
                <div className="flex items-center gap-2 text-sm">
                  <AlertTriangle className="h-4 w-4 text-orange-600" />
                  <span className="font-semibold text-orange-600">
                    {findings.high} High
                  </span>
                </div>
              )}
              {findings.medium > 0 && (
                <div className="flex items-center gap-2 text-sm">
                  <AlertTriangle className="h-4 w-4 text-yellow-600" />
                  <span className="font-semibold text-yellow-600">
                    {findings.medium} Medium
                  </span>
                </div>
              )}
              {findings.low > 0 && (
                <div className="flex items-center gap-2 text-sm">
                  <Info className="h-4 w-4 text-blue-600" />
                  <span className="text-blue-600">{findings.low} Low</span>
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center gap-2 text-sm">
              <Shield className="h-4 w-4 text-green-600" />
              <span className="font-medium text-green-600">
                No security findings detected
              </span>
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}
