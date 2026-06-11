/**
 * AgenticPhishDetector — DetectorPage
 *
 * Main phishing detection page. Composes the EmailForm, ExamplesCarousel,
 * ResultPanel, HighlightedBody, ToolCards, and ThinkingTrace into a
 * cohesive analysis workflow with creative animated pipeline visualization.
 */

import { useState, useCallback, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ChevronDown,
  Mail,
  Globe,
  Link as LinkIcon,
  Brain,
  Shield,
  Cpu,
  ArrowRight,
} from "lucide-react";
import { EmailForm } from "../components/EmailForm";
import { ExamplesCarousel } from "../components/ExamplesCarousel";
import { ResultPanel } from "../components/ResultPanel";
import { HighlightedBody } from "../components/HighlightedBody";
import { ToolCard } from "../components/ToolCard";
import { useAnalyze } from "../hooks/useAnalyze";
import type { Example, AnalyzeRequest } from "../types/api";

/* ── Pipeline Step Visualization ── */
const PIPELINE_STEPS = [
  { id: "supervisor", label: "Supervisor", icon: Cpu, desc: "LLM planning tool calls" },
  { id: "header", label: "Header Parser", icon: Mail, desc: "Checking email metadata" },
  { id: "whois", label: "WHOIS Lookup", icon: Globe, desc: "Analyzing domain age" },
  { id: "urlscan", label: "URL Scanner", icon: LinkIcon, desc: "Scanning URLs" },
  { id: "heuristics", label: "Heuristics", icon: Brain, desc: "NLP pattern analysis" },
  { id: "verdict", label: "Final Verdict", icon: Shield, desc: "Synthesizing result" },
];

function PipelineVisualizer() {
  const [activeStep, setActiveStep] = useState(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | undefined>(undefined);

  useEffect(() => {
    intervalRef.current = setInterval(() => {
      setActiveStep((prev) => {
        // Stop advancing once we reach the last step
        if (prev >= PIPELINE_STEPS.length - 1) {
          clearInterval(intervalRef.current);
          return prev;
        }
        return prev + 1;
      });
    }, 2400);
    return () => clearInterval(intervalRef.current);
  }, []);

  return (
    <div className="pipeline-viz">
      <div className="pipeline-header">
        <Cpu
          size={20}
          style={{ color: "var(--color-primary)", animation: "spin 2s linear infinite" }}
        />
        <span style={{ fontWeight: 600, fontSize: "var(--text-lg)" }}>
          Agent Pipeline Running
        </span>
      </div>

      <div className="pipeline-steps">
        {PIPELINE_STEPS.map((step, i) => {
          const Icon = step.icon;
          const isActive = i === activeStep;
          const isDone = i < activeStep;

          return (
            <div key={step.id} className="pipeline-step-row">
              <motion.div
                className={`pipeline-step ${isActive ? "active" : ""} ${isDone ? "done" : ""}`}
                animate={isActive ? { scale: [1, 1.05, 1] } : {}}
                transition={{ duration: 0.8, repeat: Infinity }}
              >
                <div className="pipeline-step-icon">
                  <Icon size={16} />
                </div>
                <div className="pipeline-step-info">
                  <span className="pipeline-step-label">{step.label}</span>
                  <span className="pipeline-step-desc">
                    {isActive ? step.desc : isDone ? "Complete ✓" : "Waiting..."}
                  </span>
                </div>
                {isActive && (
                  <div className="pipeline-step-pulse" />
                )}
              </motion.div>
              {i < PIPELINE_STEPS.length - 1 && (
                <ArrowRight
                  size={14}
                  className="pipeline-arrow"
                  style={{
                    color: isDone ? "var(--color-primary)" : "var(--color-text-subtle)",
                    opacity: isDone ? 1 : 0.3,
                  }}
                />
              )}
            </div>
          );
        })}
      </div>

      <div className="pipeline-bar-track">
        <motion.div
          className="pipeline-bar-fill"
          animate={{ width: `${((activeStep + 1) / PIPELINE_STEPS.length) * 100}%` }}
          transition={{ duration: 0.5, ease: "easeOut" }}
        />
      </div>
    </div>
  );
}

/* ── Main Page ── */

export function DetectorPage() {
  const { result, submittedBody, isLoading, error, analyze, reset } = useAnalyze();
  const [showThinking, setShowThinking] = useState(false);

  const handleSubmit = useCallback(
    (data: AnalyzeRequest) => {
      analyze(data);
    },
    [analyze]
  );

  const handleClear = useCallback(() => {
    reset();
    setShowThinking(false);
  }, [reset]);

  const handleExampleSelect = useCallback(
    (example: Example) => {
      const fill = (window as any).__emailFormFill;
      if (fill) {
        fill({
          sender_email: example.sender_email,
          receiver_email: example.receiver_email,
          date_time: example.date_time,
          subject: example.subject,
          body: example.body,
        });
      }
      reset();
    },
    [reset]
  );

  return (
    <main
      className="container"
      style={{ paddingTop: "var(--space-lg)", paddingBottom: "var(--space-3xl)" }}
    >
      {/* Hero */}
      <div className="hero">
        <h1 className="hero-title">AgenticPhishDetector</h1>
        <p className="hero-subtitle">
          AI-powered multi-agent phishing detection. Paste an email and let our
          LangGraph pipeline analyze it with specialized security tools.
        </p>
      </div>

      {/* Examples Carousel */}
      <ExamplesCarousel onSelect={handleExampleSelect} />

      {/* Email Form */}
      <EmailForm onSubmit={handleSubmit} isLoading={isLoading} onClear={handleClear} />

      {/* ── Creative Pipeline Loading State ── */}
      <AnimatePresence>
        {isLoading && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.4 }}
            style={{ marginBottom: "var(--space-xl)" }}
          >
            <PipelineVisualizer />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Error State */}
      {error && (
        <motion.div
          className="card"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          style={{
            borderColor: "var(--color-verdict-phishing)",
            marginBottom: "var(--space-xl)",
            padding: "var(--space-lg)",
          }}
        >
          <div
            style={{
              color: "var(--color-verdict-phishing)",
              fontWeight: 600,
              marginBottom: "var(--space-sm)",
            }}
          >
            ⚠ Analysis Error
          </div>
          <p style={{ margin: 0, fontSize: "var(--text-sm)" }}>{error}</p>
        </motion.div>
      )}

      {/* Results */}
      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease: "easeOut" }}
          >
            {/* Verdict Panel */}
            <ResultPanel result={result} />

            {/* Highlighted Body */}
            {result.highlighted_spans.length > 0 && submittedBody && (
              <div style={{ marginBottom: "var(--space-xl)" }}>
                <h3
                  style={{
                    fontSize: "var(--text-base)",
                    marginBottom: "var(--space-sm)",
                  }}
                >
                  📝 Email Body — Highlighted Evidence
                </h3>
                <HighlightedBody body={submittedBody} spans={result.highlighted_spans} />
              </div>
            )}

            {/* Tool Results */}
            {result.tool_results.length > 0 && (
              <div style={{ marginBottom: "var(--space-xl)" }}>
                <h3
                  style={{
                    fontSize: "var(--text-base)",
                    marginBottom: "var(--space-md)",
                  }}
                >
                  🔧 Tool Analysis Results
                </h3>
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "var(--space-sm)",
                  }}
                >
                  {result.tool_results.map((tr, i) => (
                    <ToolCard key={tr.tool} result={tr} index={i} />
                  ))}
                </div>
              </div>
            )}

            {/* Thinking Trace */}
            {result.thinking_trace && (
              <div
                className="thinking-trace"
                style={{ marginBottom: "var(--space-xl)" }}
              >
                <div
                  className="thinking-trace-header"
                  onClick={() => setShowThinking(!showThinking)}
                  role="button"
                  id="thinking-trace-toggle"
                >
                  <span>🧠 View AI Reasoning</span>
                  <ChevronDown
                    size={16}
                    style={{
                      transform: showThinking ? "rotate(180deg)" : "rotate(0deg)",
                      transition: "transform 0.2s ease",
                    }}
                  />
                </div>
                <AnimatePresence>
                  {showThinking && (
                    <motion.div
                      className="thinking-trace-body"
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                    >
                      {result.thinking_trace}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Empty State — subtle text only, no fishhook SVG */}
      {!result && !isLoading && !error && (
        <div
          style={{
            textAlign: "center",
            padding: "var(--space-3xl) 0",
            opacity: 0.4,
          }}
        >
          <p
            style={{
              fontSize: "var(--text-sm)",
              color: "var(--color-text-subtle)",
            }}
          >
            Paste an email above or select an example to get started
          </p>
        </div>
      )}
    </main>
  );
}
