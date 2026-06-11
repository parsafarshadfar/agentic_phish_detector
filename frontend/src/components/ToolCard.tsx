/**
 * AgenticPhishDetector — ToolCard Component
 *
 * Expandable card showing a single tool's analysis result.
 * Displays: icon, tool name, info tooltip, risk score indicator,
 * 1-sentence summary, duration, and a collapsible details panel.
 */

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronDown, Mail, Globe, Link, Brain, Shield, Info } from "lucide-react";
import type { ToolResult } from "../types/api";

interface ToolCardProps {
  result: ToolResult;
  index: number;
}

const TOOL_ICONS: Record<string, React.ReactNode> = {
  mail: <Mail size={18} />,
  globe: <Globe size={18} />,
  link: <Link size={18} />,
  brain: <Brain size={18} />,
  shield: <Shield size={18} />,
};

const TOOL_NAMES: Record<string, string> = {
  header_parser: "Header Analysis",
  whois_tool: "WHOIS Lookup",
  url_scan: "URL Scanner",
  heuristics: "Heuristic Analysis",
};

const TOOL_DESCRIPTIONS: Record<string, string> = {
  header_parser:
    "Analyzes email metadata: From/Reply-To domain mismatch, brand impersonation (e.g., PayPal from non-PayPal domain), SPF/DKIM/DMARC authentication failures, and suspicious X-Headers.",
  whois_tool:
    "Performs WHOIS lookup on the sender's domain to check registration age, registrar reputation, and geographic location. Newly registered domains (< 90 days) are a strong phishing indicator.",
  url_scan:
    "Scans all URLs found in the email body against URLScan.io's threat intelligence database. Checks for known malicious sites, suspicious redirects, and domain reputation.",
  heuristics:
    "NLP-based pattern analysis: detects urgency language ('act now', 'within 24 hours'), credential harvesting requests (passwords, SSNs), too-good-to-be-true offers, and social engineering tactics.",
};

const RISK_SCORES: Record<string, { score: number; label: string; color: string }> = {
  low: { score: 1, label: "1/4", color: "var(--color-verdict-legitimate)" },
  medium: { score: 2, label: "2/4", color: "var(--color-verdict-suspicious)" },
  high: { score: 3, label: "3/4", color: "var(--color-verdict-phishing)" },
  critical: { score: 4, label: "4/4", color: "#991b1b" },
};

export function ToolCard({ result, index }: ToolCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [showInfo, setShowInfo] = useState(false);

  const icon = TOOL_ICONS[result.icon] || TOOL_ICONS.shield;
  const name = TOOL_NAMES[result.tool] || result.tool;
  const description = TOOL_DESCRIPTIONS[result.tool] || "Analyzes email content for security threats.";
  const riskMeta = RISK_SCORES[result.risk_level] || RISK_SCORES.low;

  return (
    <motion.div
      className="tool-card"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.08, duration: 0.4, ease: "easeOut" }}
    >
      <div
        className="tool-card-header"
        onClick={() => setIsExpanded(!isExpanded)}
        role="button"
        aria-expanded={isExpanded}
        id={`tool-card-${result.tool}`}
      >
        <div className="tool-card-icon">{icon}</div>

        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "var(--space-sm)", marginBottom: "2px" }}>
            <span style={{ fontWeight: 600, fontSize: "var(--text-sm)" }}>{name}</span>

            {/* Info Icon */}
            <button
              className="tool-info-btn"
              onClick={(e) => {
                e.stopPropagation();
                setShowInfo(!showInfo);
              }}
              aria-label={`About ${name}`}
              title="Learn more about this tool"
              type="button"
            >
              <Info size={13} />
            </button>

            {/* Risk Badge */}
            <span className={`badge badge-risk-${result.risk_level}`}>
              {result.risk_level}
            </span>

            {/* Risk Score */}
            <span className="tool-risk-score" style={{ color: riskMeta.color }}>
              {riskMeta.label}
            </span>
          </div>
          <div style={{ fontSize: "var(--text-sm)", color: "var(--color-text-muted)" }}>
            {result.summary}
          </div>
        </div>

        {result.duration_ms > 0 && (
          <span style={{ fontSize: "var(--text-xs)", color: "var(--color-text-subtle)", whiteSpace: "nowrap" }}>
            {result.duration_ms}ms
          </span>
        )}

        <ChevronDown
          size={16}
          style={{
            transition: "transform 0.2s ease",
            transform: isExpanded ? "rotate(180deg)" : "rotate(0deg)",
            color: "var(--color-text-subtle)",
            flexShrink: 0,
          }}
        />
      </div>

      {/* Info Tooltip */}
      <AnimatePresence>
        {showInfo && (
          <motion.div
            className="tool-info-panel"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            <div className="tool-info-content">
              <Info size={14} style={{ flexShrink: 0, color: "var(--color-primary)", marginTop: 2 }} />
              <span>{description}</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Expandable Details */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            className="tool-card-body"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
          >
            <div className="tool-card-details">
              <pre style={{ whiteSpace: "pre-wrap", margin: 0 }}>
                {JSON.stringify(result.details, null, 2)}
              </pre>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
