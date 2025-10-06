import { useEffect, useRef, useState } from "react";
import type { NetworkNode, NetworkConnection } from "@shared/schema";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface NetworkGraphProps {
  nodes: NetworkNode[];
  connections: NetworkConnection[];
}

interface GraphNode {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  node: NetworkNode;
}

interface GraphLink {
  source: GraphNode;
  target: GraphNode;
  connection: NetworkConnection;
}

export function NetworkGraph({ nodes, connections }: NetworkGraphProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<NetworkNode | null>(null);
  const graphNodesRef = useRef<GraphNode[]>([]);
  const graphLinksRef = useRef<GraphLink[]>([]);
  const animationRef = useRef<number>();

  useEffect(() => {
    if (!canvasRef.current || nodes.length === 0) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas size
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

    // Initialize graph nodes
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    const radius = Math.min(rect.width, rect.height) * 0.35;

    graphNodesRef.current = nodes.map((node, i) => {
      const angle = (i / nodes.length) * 2 * Math.PI;
      return {
        id: node.id,
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
        vx: 0,
        vy: 0,
        node,
      };
    });

    // Initialize graph links
    graphLinksRef.current = connections.map(conn => {
      const source = graphNodesRef.current.find(n => n.node.ipAddress === conn.sourceIP);
      const target = graphNodesRef.current.find(n => n.node.ipAddress === conn.destIP);
      if (!source || !target) return null;
      return { source, target, connection: conn };
    }).filter(Boolean) as GraphLink[];

    // Force simulation
    const simulate = () => {
      const alpha = 0.02;
      const linkDistance = 100;
      const repulsion = 3000;

      // Apply forces
      graphLinksRef.current.forEach(link => {
        const dx = link.target.x - link.source.x;
        const dy = link.target.y - link.source.y;
        const distance = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (distance - linkDistance) * alpha;
        const fx = (dx / distance) * force;
        const fy = (dy / distance) * force;

        link.source.vx += fx;
        link.source.vy += fy;
        link.target.vx -= fx;
        link.target.vy -= fy;
      });

      // Repulsion between nodes
      graphNodesRef.current.forEach(nodeA => {
        graphNodesRef.current.forEach(nodeB => {
          if (nodeA === nodeB) return;
          const dx = nodeB.x - nodeA.x;
          const dy = nodeB.y - nodeA.y;
          const distance = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = repulsion / (distance * distance);
          const fx = (dx / distance) * force;
          const fy = (dy / distance) * force;

          nodeA.vx -= fx;
          nodeA.vy -= fy;
        });
      });

      // Update positions
      graphNodesRef.current.forEach(node => {
        node.x += node.vx;
        node.y += node.vy;
        node.vx *= 0.8;
        node.vy *= 0.8;

        // Keep nodes within bounds
        const padding = 30;
        node.x = Math.max(padding, Math.min(rect.width - padding, node.x));
        node.y = Math.max(padding, Math.min(rect.height - padding, node.y));
      });
    };

    // Render function
    const render = () => {
      if (!ctx) return;

      ctx.clearRect(0, 0, rect.width, rect.height);

      // Draw connections
      graphLinksRef.current.forEach(link => {
        ctx.beginPath();
        ctx.moveTo(link.source.x, link.source.y);
        ctx.lineTo(link.target.x, link.target.y);
        ctx.strokeStyle = getComputedStyle(document.documentElement)
          .getPropertyValue('--border').trim() || '#e5e7eb';
        ctx.lineWidth = Math.min(link.connection.packetCount / 10, 3);
        ctx.stroke();
      });

      // Draw nodes
      graphNodesRef.current.forEach(graphNode => {
        const isSelected = selectedNode?.id === graphNode.node.id;
        const isHovered = hoveredNode?.id === graphNode.node.id;
        const nodeRadius = isSelected ? 12 : isHovered ? 10 : 8;

        ctx.beginPath();
        ctx.arc(graphNode.x, graphNode.y, nodeRadius, 0, 2 * Math.PI);
        
        // Node fill color based on type
        const colors = {
          router: '#3b82f6',
          server: '#10b981',
          client: '#8b5cf6',
          unknown: '#6b7280',
        };
        ctx.fillStyle = colors[graphNode.node.nodeType] || colors.unknown;
        ctx.fill();

        // Draw border for selected/hovered
        if (isSelected || isHovered) {
          ctx.strokeStyle = isSelected ? '#2563eb' : '#94a3b8';
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        // Draw IP label
        ctx.fillStyle = getComputedStyle(document.documentElement)
          .getPropertyValue('--foreground').trim() || '#000';
        ctx.font = '10px monospace';
        ctx.textAlign = 'center';
        ctx.fillText(graphNode.node.ipAddress, graphNode.x, graphNode.y - 15);
      });

      simulate();
      animationRef.current = requestAnimationFrame(render);
    };

    render();

    // Mouse interaction
    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      const node = graphNodesRef.current.find(n => {
        const dx = n.x - x;
        const dy = n.y - y;
        return Math.sqrt(dx * dx + dy * dy) < 12;
      });

      setHoveredNode(node?.node || null);
    };

    const handleClick = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      const node = graphNodesRef.current.find(n => {
        const dx = n.x - x;
        const dy = n.y - y;
        return Math.sqrt(dx * dx + dy * dy) < 12;
      });

      setSelectedNode(node?.node || null);
    };

    canvas.addEventListener('mousemove', handleMouseMove);
    canvas.addEventListener('click', handleClick);

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
      canvas.removeEventListener('mousemove', handleMouseMove);
      canvas.removeEventListener('click', handleClick);
    };
  }, [nodes, connections, selectedNode, hoveredNode]);

  if (nodes.length === 0) {
    return (
      <Card className="p-12">
        <div className="flex flex-col items-center justify-center text-muted-foreground">
          <p>No network nodes to display</p>
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="relative">
        <canvas
          ref={canvasRef}
          className="w-full h-[400px] border rounded-md bg-card"
          data-testid="canvas-network-graph"
        />
        
        <div className="absolute top-4 right-4 flex gap-2">
          <Badge variant="outline" className="bg-card">
            <div className="w-3 h-3 rounded-full bg-blue-500 mr-2" />
            Router
          </Badge>
          <Badge variant="outline" className="bg-card">
            <div className="w-3 h-3 rounded-full bg-green-500 mr-2" />
            Server
          </Badge>
          <Badge variant="outline" className="bg-card">
            <div className="w-3 h-3 rounded-full bg-purple-500 mr-2" />
            Client
          </Badge>
        </div>
      </div>

      {selectedNode && (
        <Card className="p-4" data-testid="card-selected-node">
          <h3 className="font-semibold mb-2">Node Details</h3>
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div className="text-muted-foreground">IP Address:</div>
            <div className="font-mono">{selectedNode.ipAddress}</div>
            
            {selectedNode.macAddress && (
              <>
                <div className="text-muted-foreground">MAC Address:</div>
                <div className="font-mono">{selectedNode.macAddress}</div>
              </>
            )}
            
            {selectedNode.hostname && (
              <>
                <div className="text-muted-foreground">Hostname:</div>
                <div className="font-mono">{selectedNode.hostname}</div>
              </>
            )}
            
            <div className="text-muted-foreground">Type:</div>
            <div className="capitalize">{selectedNode.nodeType}</div>
            
            <div className="text-muted-foreground">Packets:</div>
            <div>{selectedNode.packetCount.toLocaleString()}</div>
            
            <div className="text-muted-foreground">Protocols:</div>
            <div className="flex gap-1 flex-wrap">
              {selectedNode.protocols.map(proto => (
                <Badge key={proto} variant="secondary" className="text-xs">
                  {proto}
                </Badge>
              ))}
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
