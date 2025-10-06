import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Download, FileText, Image, File } from "lucide-react";
import type { ExtractedFile } from "@shared/schema";
import { ProtocolBadge } from "./protocol-badge";

interface FilesTableProps {
  files: ExtractedFile[];
}

export function FilesTable({ files }: FilesTableProps) {
  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  };

  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const getFileIcon = (fileType: string) => {
    if (fileType.startsWith('image/')) return Image;
    if (fileType.includes('text') || fileType.includes('json')) return FileText;
    return File;
  };

  const handleDownload = (file: ExtractedFile) => {
    // Properly convert base64 to binary data
    const binaryString = atob(file.data);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    
    const blob = new Blob([bytes], { type: file.mimeType || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.fileName;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (files.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <p>No files extracted</p>
      </div>
    );
  }

  return (
    <div className="border rounded-md">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[100px]">Time</TableHead>
            <TableHead>File Name</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Size</TableHead>
            <TableHead>Protocol</TableHead>
            <TableHead>Source</TableHead>
            <TableHead className="w-[100px]">Action</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {files.map((file) => {
            const FileIcon = getFileIcon(file.fileType);
            return (
              <TableRow key={file.id} data-testid={`row-file-${file.id}`}>
                <TableCell className="font-mono text-xs text-muted-foreground">
                  {formatTime(file.timestamp)}
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <FileIcon className="h-4 w-4 text-muted-foreground" />
                    <span className="font-mono text-sm">{file.fileName}</span>
                  </div>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {file.fileType}
                </TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">
                  {formatBytes(file.fileSize)}
                </TableCell>
                <TableCell>
                  <ProtocolBadge protocol={file.protocol} />
                </TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">
                  {file.sourceIP}
                </TableCell>
                <TableCell>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleDownload(file)}
                    data-testid={`button-download-${file.id}`}
                  >
                    <Download className="h-4 w-4" />
                  </Button>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
