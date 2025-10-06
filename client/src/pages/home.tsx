import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { FileUpload } from "@/components/file-upload";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { Network, FileText, Shield, Zap, Database, Lock } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { useMutation } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { useProgress } from "@/hooks/use-progress";

export default function Home() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const serverProgress = useProgress(analysisId);

  // Combine upload progress and server progress
  const progress = isUploading && uploadProgress !== null
    ? { progress: uploadProgress, message: 'Uploading file...', status: 'uploading' as const, currentStep: 'uploading' }
    : serverProgress;

  const uploadMutation = useMutation({
    mutationFn: async (file: File) => {
      return new Promise<any>((resolve, reject) => {
        const formData = new FormData();
        formData.append('pcap', file);
        
        const xhr = new XMLHttpRequest();
        
        // Track upload progress
        xhr.upload.addEventListener('progress', (e) => {
          if (e.lengthComputable) {
            const percentComplete = Math.round((e.loaded / e.total) * 100);
            setUploadProgress(percentComplete);
          }
        });
        
        xhr.addEventListener('load', () => {
          if (xhr.status === 200) {
            try {
              const data = JSON.parse(xhr.responseText);
              setIsUploading(false);
              setUploadProgress(null);
              resolve(data);
            } catch (error) {
              reject(new Error('Failed to parse response'));
            }
          } else {
            reject(new Error('Upload failed'));
          }
        });
        
        xhr.addEventListener('error', () => {
          reject(new Error('Upload failed'));
        });
        
        xhr.open('POST', '/api/upload');
        xhr.send(formData);
      });
    },
    onSuccess: (data) => {
      setAnalysisId(data.id);
    },
    onError: (error: Error) => {
      toast({
        title: "Upload Failed",
        description: error.message,
        variant: "destructive",
      });
      setAnalysisId(null);
      setIsUploading(false);
      setUploadProgress(null);
    },
  });

  const handleFileSelect = (file: File) => {
    setIsUploading(true);
    setUploadProgress(0);
    uploadMutation.mutate(file);
  };

  // Navigate to analysis page when completed
  useEffect(() => {
    if (progress?.status === 'completed' && analysisId) {
      setLocation(`/analysis/${analysisId}`);
    }
  }, [progress?.status, analysisId, setLocation]);

  const features = [
    {
      icon: Network,
      title: "Network Visualization",
      description: "Interactive network maps showing device connections and traffic flows",
      color: "text-chart-2",
    },
    {
      icon: FileText,
      title: "Protocol Analysis",
      description: "Deep inspection of HTTP, DNS, TCP, UDP and other network protocols",
      color: "text-protocol-http",
    },
    {
      icon: Database,
      title: "File Extraction",
      description: "Automatically extract images, documents, and files from network traffic",
      color: "text-chart-3",
    },
    {
      icon: Shield,
      title: "Credential Detection",
      description: "Discover plaintext passwords and authentication credentials",
      color: "text-destructive",
    },
    {
      icon: Zap,
      title: "Instant Analysis",
      description: "Fast PCAP processing with real-time results and insights",
      color: "text-chart-1",
    },
    {
      icon: Lock,
      title: "Local Processing",
      description: "All analysis happens in your browser - your data stays private",
      color: "text-chart-5",
    },
  ];

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b sticky top-0 bg-background/80 backdrop-blur-sm z-50">
        <div className="container mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Network className="h-6 w-6 text-primary" />
            <h1 className="text-xl font-semibold">PCAP Analyzer</h1>
          </div>
          <ThemeToggle />
        </div>
      </header>

      {/* Hero Section */}
      <section className="container mx-auto px-6 py-20">
        <div className="max-w-4xl mx-auto text-center space-y-8">
          <div className="space-y-4">
            <h2 className="text-5xl font-bold tracking-tight">
              Analyze Network Traffic
              <span className="text-primary"> Instantly</span>
            </h2>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              Upload PCAP files and visualize network flows, decode protocols, 
              extract files, and discover credentials with our powerful analysis tool.
            </p>
          </div>

          <div className="flex items-center justify-center gap-3 text-sm text-muted-foreground">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-green-500" />
              <span>No Installation</span>
            </div>
            <div className="h-4 w-px bg-border" />
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-blue-500" />
              <span>Works Locally</span>
            </div>
            <div className="h-4 w-px bg-border" />
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-purple-500" />
              <span>Free to Use</span>
            </div>
          </div>

          {/* Upload Zone */}
          <div className="max-w-2xl mx-auto pt-8">
            {progress ? (
              <Card className="p-12">
                <div className="flex flex-col items-center gap-6">
                  <div className="h-12 w-12 rounded-full border-4 border-primary border-t-transparent animate-spin" />
                  <div className="w-full max-w-md space-y-3">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">{progress.message}</span>
                      <span className="font-semibold">{Math.round(progress.progress)}%</span>
                    </div>
                    <Progress value={progress.progress} className="h-2" />
                    {progress.currentStep && (
                      <p className="text-xs text-muted-foreground text-center capitalize">
                        {progress.currentStep}
                      </p>
                    )}
                  </div>
                </div>
              </Card>
            ) : (
              <FileUpload onFileSelect={handleFileSelect} />
            )}
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section className="container mx-auto px-6 py-20">
        <div className="max-w-6xl mx-auto">
          <div className="text-center space-y-4 mb-12">
            <h3 className="text-3xl font-bold">Powerful Features</h3>
            <p className="text-muted-foreground">
              Everything you need for comprehensive network traffic analysis
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature, index) => (
              <Card key={index} className="hover-elevate transition-all" data-testid={`card-feature-${index}`}>
                <CardHeader>
                  <CardTitle className="flex items-center gap-3">
                    <div className={`p-2 rounded-md bg-muted ${feature.color}`}>
                      <feature.icon className="h-5 w-5" />
                    </div>
                    <span className="text-base">{feature.title}</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground">
                    {feature.description}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="container mx-auto px-6 py-20">
        <Card className="max-w-4xl mx-auto p-12 text-center bg-gradient-to-br from-primary/5 to-chart-1/5 border-primary/20">
          <h3 className="text-3xl font-bold mb-4">Ready to Analyze?</h3>
          <p className="text-muted-foreground mb-8 max-w-2xl mx-auto">
            Upload your PCAP file now and get instant insights into your network traffic. 
            Supports .pcap and .pcapng formats up to 25MB.
          </p>
          <Button
            size="lg"
            onClick={() => document.querySelector<HTMLInputElement>('[data-testid="input-file"]')?.click()}
            data-testid="button-upload-cta"
          >
            <Network className="mr-2 h-5 w-5" />
            Upload PCAP File
          </Button>
        </Card>
      </section>

      {/* Footer */}
      <footer className="border-t mt-20">
        <div className="container mx-auto px-6 py-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <p className="text-sm text-muted-foreground">
              PCAP Analyzer - Network Traffic Analysis Tool
            </p>
            <p className="text-xs text-muted-foreground">
              Supports PCAP and PCAPNG file formats
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
