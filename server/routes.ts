import type { Express } from "express";
import { createServer, type Server } from "http";
import multer from "multer";
import { storage } from "./storage";
import { analyzePcapFile } from "./pcap-analyzer";
import { progressTracker } from "./progress-tracker";
import { promises as fs } from "fs";
import path from "path";
import os from "os";
import { randomUUID } from "crypto";

const upload = multer({
  dest: path.join(os.tmpdir(), 'pcap-uploads'),
  limits: {
    fileSize: 25 * 1024 * 1024, // 25MB
  },
  fileFilter: (_req, file, cb) => {
    const validExtensions = ['.pcap', '.pcapng', '.cap'];
    const ext = path.extname(file.originalname).toLowerCase();
    
    if (validExtensions.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only .pcap, .pcapng, and .cap files are allowed.'));
    }
  },
});

export async function registerRoutes(app: Express): Promise<Server> {
  // SSE endpoint for progress updates
  app.get('/api/progress/:id', (req, res) => {
    const { id } = req.params;

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    progressTracker.addConnection(id, res);

    req.on('close', () => {
      progressTracker.removeConnection(id, res);
    });
  });

  // Upload and analyze PCAP file
  app.post('/api/upload', upload.single('pcap'), async (req, res) => {
    const analysisId = randomUUID();
    
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
      }

      const { originalname, size, path: filePath } = req.file;

      // Send initial response with analysis ID
      res.json({ id: analysisId, status: 'processing' });

      // Start analysis asynchronously with progress tracking
      progressTracker.updateProgress({
        id: analysisId,
        status: 'uploading',
        progress: 5,
        message: 'File uploaded successfully',
      });

      const result = await analyzePcapFile(
        filePath,
        originalname,
        size,
        analysisId,
        (progress, message, step) => {
          const statusMap: Record<string, 'uploading' | 'parsing' | 'analyzing' | 'finalizing' | 'completed'> = {
            'parsing': 'parsing',
            'analyzing': 'analyzing',
            'finalizing': 'finalizing',
            'completed': 'completed',
          };
          
          progressTracker.updateProgress({
            id: analysisId,
            status: statusMap[step || 'analyzing'] || 'analyzing',
            progress,
            message,
            currentStep: step,
          });
        }
      );

      // Save analysis to storage
      await storage.saveAnalysis(result);

      // Clean up uploaded file
      await fs.unlink(filePath).catch(() => {});

      // Send final progress update
      progressTracker.updateProgress({
        id: analysisId,
        status: 'completed',
        progress: 100,
        message: 'Analysis completed successfully',
      });

    } catch (error) {
      console.error('Error analyzing PCAP:', error);
      
      progressTracker.updateProgress({
        id: analysisId,
        status: 'error',
        progress: 0,
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  // Get analysis by ID
  app.get('/api/analysis/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const analysis = await storage.getAnalysis(id);

      if (!analysis) {
        return res.status(404).json({ error: 'Analysis not found' });
      }

      res.json(analysis);
    } catch (error) {
      console.error('Error fetching analysis:', error);
      res.status(500).json({ error: 'Failed to fetch analysis' });
    }
  });

  // Get all analyses
  app.get('/api/analyses', async (_req, res) => {
    try {
      const analyses = await storage.getAllAnalyses();
      res.json(analyses);
    } catch (error) {
      console.error('Error fetching analyses:', error);
      res.status(500).json({ error: 'Failed to fetch analyses' });
    }
  });

  const httpServer = createServer(app);

  return httpServer;
}
