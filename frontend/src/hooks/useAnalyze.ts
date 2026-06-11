/**
 * AgenticPhishDetector — useAnalyze Hook
 *
 * Custom React hook that handles the email analysis API call.
 * Sends POST /api/analyze and returns the analysis results.
 * Preserves the submitted body text for HighlightedBody rendering.
 */

import { useState, useCallback } from "react";
import type { AnalyzeRequest, AnalyzeResponse } from "../types/api";

/** API base URL — empty string uses Vite proxy in dev, set VITE_API_URL or defaults to '/agenticphishdetector' in production */
const API_BASE = import.meta.env.VITE_API_URL || (import.meta.env.PROD ? "/agenticphishdetector" : "");

interface UseAnalyzeReturn {
  result: AnalyzeResponse | null;
  submittedBody: string;
  isLoading: boolean;
  error: string | null;
  analyze: (request: AnalyzeRequest) => Promise<void>;
  reset: () => void;
}

export function useAnalyze(): UseAnalyzeReturn {
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [submittedBody, setSubmittedBody] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const analyze = useCallback(async (request: AnalyzeRequest) => {
    setIsLoading(true);
    setError(null);
    setResult(null);
    setSubmittedBody(request.body);

    try {
      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(
          errorData.detail || `Analysis failed with status ${response.status}`
        );
      }

      const data: AnalyzeResponse = await response.json();
      setResult(data);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "An unexpected error occurred";
      setError(message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const reset = useCallback(() => {
    setResult(null);
    setError(null);
    setIsLoading(false);
    setSubmittedBody("");
  }, []);

  return { result, submittedBody, isLoading, error, analyze, reset };
}
