import { useEffect, useState } from 'react';

export interface ProgressUpdate {
  id: string;
  status: 'uploading' | 'parsing' | 'analyzing' | 'finalizing' | 'completed' | 'error';
  progress: number;
  message: string;
  currentStep?: string;
}

export function useProgress(analysisId: string | null) {
  const [progress, setProgress] = useState<ProgressUpdate | null>(null);

  useEffect(() => {
    if (!analysisId) {
      setProgress(null);
      return;
    }

    const eventSource = new EventSource(`/api/progress/${analysisId}`);

    eventSource.onmessage = (event) => {
      try {
        const update: ProgressUpdate = JSON.parse(event.data);
        setProgress(update);

        if (update.status === 'completed' || update.status === 'error') {
          eventSource.close();
        }
      } catch (err) {
        console.error('Error parsing progress update:', err);
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [analysisId]);

  return progress;
}
