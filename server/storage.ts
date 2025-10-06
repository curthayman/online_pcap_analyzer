import type { AnalysisResult } from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  saveAnalysis(analysis: AnalysisResult): Promise<AnalysisResult>;
  getAnalysis(id: string): Promise<AnalysisResult | undefined>;
  getAllAnalyses(): Promise<AnalysisResult[]>;
}

export class MemStorage implements IStorage {
  private analyses: Map<string, AnalysisResult>;

  constructor() {
    this.analyses = new Map();
  }

  async saveAnalysis(analysis: AnalysisResult): Promise<AnalysisResult> {
    this.analyses.set(analysis.analysis.id, analysis);
    return analysis;
  }

  async getAnalysis(id: string): Promise<AnalysisResult | undefined> {
    return this.analyses.get(id);
  }

  async getAllAnalyses(): Promise<AnalysisResult[]> {
    return Array.from(this.analyses.values());
  }
}

export const storage = new MemStorage();
