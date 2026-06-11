/**
 * AgenticPhishDetector — ResultPanel Component
 *
 * Displays the analysis verdict with:
 * - Verdict badge (PHISHING/SUSPICIOUS/LEGITIMATE) with appropriate color
 * - Confidence gauge (SVG circular arc)
 * - Per-tool risk breakdown
 * - Summary text
 * - Processing time
 */

import { motion } from "framer-motion";
import { ShieldAlert, ShieldCheck, ShieldQuestion, Clock } from "lucide-react";
import type { AnalyzeResponse, RiskLevel } from "../types/api";

interface ResultPanelProps {
  result: AnalyzeResponse;
}

function ConfidenceGauge({ confidence, verdict }: { confidence: number; verdict: string }) {
  const radius = 48;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - confidence);

  const colorMap: Record<string, string> = {
    PHISHING: "var(--color-verdict-phishing)",
    SUSPICIOUS: "var(--color-verdict-suspicious)",
    LEGITIMATE: "var(--color-verdict-legitimate)",
  };

  const color = colorMap[verdict] || "var(--color-primary)";

  return (
    <div className="confidence-gauge">
      <svg width="120" height="120" viewBox="0 0 120 120">
        <circle className="track" cx="60" cy="60" r={radius} />
        <circle
          className="fill"
          cx="60" cy="60" r={radius}
          stroke={color}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="value" style={{ color }}>
        {Math.round(confidence * 100)}%
      </div>
    </div>
  );
}

const RISK_COLORS: Record<RiskLevel, string> = {
  low: "var(--color-verdict-legitimate)",
  medium: "var(--color-verdict-suspicious)",
  high: "var(--color-verdict-phishing)",
  critical: "#991b1b",
};

const TOOL_LABELS: Record<string, string> = {
  header_parser: "Headers",
  whois_tool: "WHOIS",
  url_scan: "URLs",
  heuristics: "NLP",
};

function ToolRiskBar({ tool, riskLevel }: { tool: string; riskLevel: RiskLevel }) {
  const riskValue: Record<RiskLevel, number> = { low: 25, medium: 50, high: 75, critical: 100 };
  const width = riskValue[riskLevel] || 25;
  const color = RISK_COLORS[riskLevel] || RISK_COLORS.low;
  const label = TOOL_LABELS[tool] || tool;

  return (
    <div style={{ display: "flex", alignItems: "center", gap: "var(--space-sm)", fontSize: "0.65rem" }}>
      <span style={{ width: 48, textAlign: "right", color: "var(--color-text-subtle)", flexShrink: 0 }}>
        {label}
      </span>
      <div
        style={{
          flex: 1,
          height: 6,
          background: "var(--color-surface-offset)",
          borderRadius: 3,
          overflow: "hidden",
        }}
      >
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${width}%` }}
          transition={{ duration: 0.8, ease: "easeOut", delay: 0.3 }}
          style={{ height: "100%", background: color, borderRadius: 3 }}
        />
      </div>
      <span
        style={{
          width: 48,
          fontFamily: "var(--font-mono)",
          fontWeight: 600,
          color,
          textTransform: "uppercase",
          flexShrink: 0,
        }}
      >
        {riskLevel}
      </span>
    </div>
  );
}

export function ResultPanel({ result }: ResultPanelProps) {
  const verdictConfig = {
    PHISHING: {
      icon: <ShieldAlert size={24} />,
      className: "badge-phishing",
      glowShadow: "var(--shadow-glow-phishing)",
    },
    SUSPICIOUS: {
      icon: <ShieldQuestion size={24} />,
      className: "badge-suspicious",
      glowShadow: "none",
    },
    LEGITIMATE: {
      icon: <ShieldCheck size={24} />,
      className: "badge-legitimate",
      glowShadow: "var(--shadow-glow-legitimate)",
    },
  };

  const config = verdictConfig[result.verdict] || verdictConfig.SUSPICIOUS;

  return (
    <motion.div
      className="card"
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ type: "spring", stiffness: 300, damping: 25 }}
      style={{
        marginBottom: "var(--space-xl)",
        boxShadow: config.glowShadow,
        borderColor: result.verdict === "PHISHING"
          ? "var(--color-verdict-phishing)"
          : result.verdict === "LEGITIMATE"
          ? "var(--color-verdict-legitimate)"
          : "var(--color-border)",
      }}
      id="result-panel"
    >
      <div style={{
        display: "flex",
        alignItems: "center",
        gap: "var(--space-xl)",
        flexWrap: "wrap",
      }}>
        {/* Confidence Gauge */}
        <ConfidenceGauge confidence={result.confidence} verdict={result.verdict} />

        {/* Verdict & Summary */}
        <div style={{ flex: 1, minWidth: 250 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "var(--space-md)", marginBottom: "var(--space-sm)" }}>
            <span className={`badge ${config.className}`} style={{ fontSize: "var(--text-sm)", padding: "0.4rem 1rem" }}>
              {config.icon}
              {result.verdict}
            </span>
          </div>

          <p style={{ fontSize: "var(--text-base)", color: "var(--color-text)", margin: 0, lineHeight: 1.6 }}>
            {result.summary}
          </p>

          <div style={{
            display: "flex",
            alignItems: "center",
            gap: "var(--space-xs)",
            marginTop: "var(--space-md)",
            fontSize: "var(--text-xs)",
            color: "var(--color-text-subtle)",
          }}>
            <Clock size={12} />
            Processed in {result.processing_time_ms.toLocaleString()}ms
          </div>
        </div>
      </div>

      {/* Per-Tool Risk Breakdown */}
      {result.tool_results.length > 0 && (
        <div style={{
          marginTop: "var(--space-lg)",
          paddingTop: "var(--space-md)",
          borderTop: "1px solid var(--color-border-subtle)",
        }}>
          <div style={{
            fontSize: "var(--text-xs)",
            color: "var(--color-text-subtle)",
            marginBottom: "var(--space-sm)",
            fontWeight: 500,
          }}>
            Risk Breakdown by Tool
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-xs)" }}>
            {result.tool_results.map((tr) => (
              <ToolRiskBar key={tr.tool} tool={tr.tool} riskLevel={tr.risk_level} />
            ))}
          </div>
        </div>
      )}
    </motion.div>
  );
}
