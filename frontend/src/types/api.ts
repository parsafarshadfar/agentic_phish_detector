/**
 * AgenticPhishDetector — API Type Definitions
 *
 * Strict TypeScript interfaces mirroring the backend Pydantic models.
 * Used by all components and hooks to ensure type safety across
 * the frontend-backend boundary.
 */

export type Verdict = "PHISHING" | "LEGITIMATE" | "SUSPICIOUS";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type Severity = "low" | "medium" | "high" | "critical";

/** Request body for POST /api/analyze */
export interface AnalyzeRequest {
  sender_email?: string | null;
  receiver_email?: string | null;
  date_time?: string | null;
  subject?: string | null;
  body: string;
}

/** A highlighted span in the email body indicating a phishing indicator */
export interface HighlightSpan {
  start: number;
  end: number;
  reason: string;
  severity: Severity;
}

/** Result from a single analysis tool */
export interface ToolResult {
  tool: string;
  icon: string;
  summary: string;
  details: Record<string, unknown>;
  risk_level: RiskLevel;
  duration_ms: number;
}

/** Full response from POST /api/analyze */
export interface AnalyzeResponse {
  verdict: Verdict;
  confidence: number;
  summary: string;
  highlighted_spans: HighlightSpan[];
  tool_results: ToolResult[];
  thinking_trace: string;
  processing_time_ms: number;
}

/** Example email for the carousel */
export interface Example {
  id: number;
  label: Verdict;
  description: string;
  sender_email: string | null;
  receiver_email: string | null;
  date_time: string | null;
  subject: string | null;
  body: string;
}
