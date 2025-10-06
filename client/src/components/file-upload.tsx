import { Upload, FileText } from "lucide-react";
import { useState, useCallback } from "react";
import { cn } from "@/lib/utils";

interface FileUploadProps {
  onFileSelect: (file: File) => void;
  maxSize?: number;
}

export function FileUpload({ onFileSelect, maxSize = 25 * 1024 * 1024 }: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const validateFile = (file: File): string | null => {
    const validExtensions = ['.pcap', '.pcapng', '.cap'];
    const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
    
    if (!validExtensions.includes(fileExtension)) {
      return `Invalid file type. Please upload a PCAP or PCAPNG file.`;
    }
    
    if (file.size > maxSize) {
      return `File too large. Maximum size is ${maxSize / (1024 * 1024)}MB.`;
    }
    
    return null;
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    setError(null);

    const file = e.dataTransfer.files[0];
    if (file) {
      const validationError = validateFile(file);
      if (validationError) {
        setError(validationError);
      } else {
        onFileSelect(file);
      }
    }
  }, [onFileSelect, maxSize]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setError(null);
    const file = e.target.files?.[0];
    if (file) {
      const validationError = validateFile(file);
      if (validationError) {
        setError(validationError);
      } else {
        onFileSelect(file);
      }
    }
  }, [onFileSelect, maxSize]);

  return (
    <div className="w-full">
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={cn(
          "relative border-2 border-dashed rounded-md transition-all duration-200",
          "flex flex-col items-center justify-center p-12 cursor-pointer",
          "hover-elevate active-elevate-2",
          isDragging 
            ? "border-primary bg-primary/5 scale-[1.02]" 
            : "border-border bg-card",
          error && "border-destructive"
        )}
        data-testid="dropzone-upload"
      >
        <input
          type="file"
          onChange={handleFileInput}
          accept=".pcap,.pcapng,.cap"
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          data-testid="input-file"
        />
        
        <div className="flex flex-col items-center gap-4 pointer-events-none">
          <div className={cn(
            "p-6 rounded-full transition-colors",
            isDragging ? "bg-primary/10" : "bg-muted"
          )}>
            {isDragging ? (
              <FileText className="h-12 w-12 text-primary" />
            ) : (
              <Upload className="h-12 w-12 text-muted-foreground" />
            )}
          </div>
          
          <div className="text-center space-y-2">
            <h3 className="text-lg font-semibold text-foreground">
              {isDragging ? "Drop PCAP file here" : "Upload PCAP File"}
            </h3>
            <p className="text-sm text-muted-foreground">
              Drag and drop or click to browse
            </p>
            <p className="text-xs text-muted-foreground">
              Supports .pcap, .pcapng files (max {maxSize / (1024 * 1024)}MB)
            </p>
          </div>
        </div>
      </div>
      
      {error && (
        <p className="mt-3 text-sm text-destructive text-center" data-testid="text-error">
          {error}
        </p>
      )}
    </div>
  );
}
