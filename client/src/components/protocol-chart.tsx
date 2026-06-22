import { Card } from "@/components/ui/card";
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts";

interface ProtocolChartProps {
  protocolDistribution: Record<string, number>;
  totalPackets: number;
}

const COLORS = [
  '#3498db', // Blue
  '#e74c3c', // Red
  '#2ecc71', // Green
  '#f39c12', // Orange
  '#9b59b6', // Purple
  '#1abc9c', // Turquoise
  '#34495e', // Dark gray
  '#95a5a6', // Gray
  '#e67e22', // Carrot
  '#16a085', // Green sea
];

export function ProtocolChart({ protocolDistribution, totalPackets }: ProtocolChartProps) {
  const maxDisplayItems = 8;

  // Sort by count and get top items
  const sortedProtocols = Object.entries(protocolDistribution)
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxDisplayItems);

  // Calculate "Other" if needed
  const displayedCount = sortedProtocols.reduce((sum, [, count]) => sum + count, 0);
  const otherCount = totalPackets - displayedCount;

  const data = sortedProtocols.map(([protocol, count]) => ({
    name: protocol,
    value: count,
    percentage: ((count / totalPackets) * 100).toFixed(1),
  }));

  if (otherCount > 0) {
    data.push({
      name: 'Other',
      value: otherCount,
      percentage: ((otherCount / totalPackets) * 100).toFixed(1),
    });
  }

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <Card className="p-3 bg-background border shadow-lg">
          <p className="font-semibold">{data.name}</p>
          <p className="text-sm text-muted-foreground">
            {data.value.toLocaleString()} packets
          </p>
          <p className="text-sm text-primary font-medium">
            {data.percentage}%
          </p>
        </Card>
      );
    }
    return null;
  };

  return (
    <Card className="p-6">
      <h3 className="text-lg font-semibold mb-4">Protocol Distribution</h3>
      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={({ percentage }) => `${percentage}%`}
            outerRadius={100}
            fill="#8884d8"
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
          <Legend
            verticalAlign="bottom"
            height={36}
            formatter={(value, entry: any) => (
              <span className="text-sm">
                {value} ({entry.payload.percentage}%)
              </span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>

      {/* Grid view below chart */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
        {data.map((item, index) => (
          <div
            key={item.name}
            className="border rounded-md p-3 bg-card hover:shadow-md transition-shadow"
          >
            <div className="flex items-center gap-2 mb-2">
              <div
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: COLORS[index % COLORS.length] }}
              />
              <p className="text-sm font-medium">{item.name}</p>
            </div>
            <p className="text-2xl font-bold">{item.value.toLocaleString()}</p>
            <p className="text-xs text-muted-foreground">{item.percentage}%</p>
          </div>
        ))}
      </div>
    </Card>
  );
}
