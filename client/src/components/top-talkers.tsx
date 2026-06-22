import { Card } from "@/components/ui/card";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import type { PcapStatistics } from "@shared/schema";

interface TopTalkersProps {
  topTalkers: PcapStatistics['topTalkers'];
}

const COLORS = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', '#34495e', '#95a5a6', '#e67e22', '#16a085'];

export function TopTalkers({ topTalkers }: TopTalkersProps) {
  if (!topTalkers || topTalkers.length === 0) {
    return null;
  }

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

  // Detect if we're showing IP addresses or MAC addresses
  const isMAC = topTalkers.length > 0 && topTalkers[0].ip.includes(':');
  const addressLabel = isMAC ? 'MAC Address' : 'IP Address';

  const data = topTalkers.slice(0, 10).map((talker) => ({
    ip: talker.ip,
    packets: talker.packets,
    bytes: talker.bytes,
    bytesFormatted: formatBytes(talker.bytes),
  }));

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <Card className="p-3 bg-background border shadow-lg">
          <p className="font-semibold text-sm mb-1">{data.ip}</p>
          <p className="text-xs text-muted-foreground">
            Packets: <span className="font-medium text-foreground">{data.packets.toLocaleString()}</span>
          </p>
          <p className="text-xs text-muted-foreground">
            Data: <span className="font-medium text-foreground">{data.bytesFormatted}</span>
          </p>
        </Card>
      );
    }
    return null;
  };

  return (
    <Card className="p-6">
      <h3 className="text-lg font-semibold mb-4">Top Talkers</h3>
      <p className="text-sm text-muted-foreground mb-4">
        Top {data.length} hosts by packet count ({addressLabel})
      </p>

      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data} layout="horizontal">
          <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
          <XAxis
            type="number"
            tick={{ fontSize: 12 }}
            tickFormatter={(value) => value.toLocaleString()}
          />
          <YAxis
            type="category"
            dataKey="ip"
            width={120}
            tick={{ fontSize: 11 }}
          />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="packets" radius={[0, 4, 4, 0]}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      {/* Table view */}
      <div className="mt-6 border rounded-md overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-muted">
            <tr>
              <th className="text-left p-3 font-medium">#</th>
              <th className="text-left p-3 font-medium">{addressLabel}</th>
              <th className="text-right p-3 font-medium">Packets</th>
              <th className="text-right p-3 font-medium">Data</th>
            </tr>
          </thead>
          <tbody>
            {data.map((talker, index) => (
              <tr key={talker.ip} className="border-t hover:bg-muted/50">
                <td className="p-3 text-muted-foreground">{index + 1}</td>
                <td className="p-3 font-mono text-xs">{talker.ip}</td>
                <td className="p-3 text-right font-medium">
                  {talker.packets.toLocaleString()}
                </td>
                <td className="p-3 text-right text-muted-foreground">
                  {talker.bytesFormatted}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
