import type { Response } from 'express';

export interface ProgressUpdate {
  id: string;
  status: 'uploading' | 'parsing' | 'analyzing' | 'finalizing' | 'completed' | 'error';
  progress: number;
  message: string;
  currentStep?: string;
}

class ProgressTracker {
  private connections: Map<string, Response[]> = new Map();
  private progress: Map<string, ProgressUpdate> = new Map();

  addConnection(id: string, res: Response) {
    const connections = this.connections.get(id) || [];
    connections.push(res);
    this.connections.set(id, connections);

    // Send current progress if exists
    const currentProgress = this.progress.get(id);
    if (currentProgress) {
      res.write(`data: ${JSON.stringify(currentProgress)}\n\n`);
    }
  }

  removeConnection(id: string, res: Response) {
    const connections = this.connections.get(id) || [];
    const filtered = connections.filter(c => c !== res);
    if (filtered.length === 0) {
      this.connections.delete(id);
    } else {
      this.connections.set(id, filtered);
    }
  }

  updateProgress(update: ProgressUpdate) {
    this.progress.set(update.id, update);

    const connections = this.connections.get(update.id) || [];
    const data = `data: ${JSON.stringify(update)}\n\n`;

    connections.forEach(res => {
      try {
        res.write(data);
      } catch (err) {
        // Connection closed
      }
    });

    // Clean up completed/error states after broadcasting
    if (update.status === 'completed' || update.status === 'error') {
      setTimeout(() => {
        this.progress.delete(update.id);
        const conns = this.connections.get(update.id);
        conns?.forEach(res => {
          try {
            res.end();
          } catch (err) {
            // Ignore
          }
        });
        this.connections.delete(update.id);
      }, 1000);
    }
  }

  getProgress(id: string): ProgressUpdate | undefined {
    return this.progress.get(id);
  }
}

export const progressTracker = new ProgressTracker();
