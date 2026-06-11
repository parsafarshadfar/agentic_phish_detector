/**
 * AgenticPhishDetector — HighlightedBody Component
 *
 * Renders the email body with color-coded highlighted spans indicating
 * phishing indicators. Each span has a tooltip showing the reason and severity.
 * Uses character offsets from the API response — never dangerouslySetInnerHTML.
 */

import { useState } from "react";
import type { HighlightSpan } from "../types/api";

interface HighlightedBodyProps {
  body: string;
  spans: HighlightSpan[];
}

export function HighlightedBody({ body, spans }: HighlightedBodyProps) {
  const [activeTooltip, setActiveTooltip] = useState<number | null>(null);

  if (!spans.length) {
    return (
      <div className="highlighted-body">
        {body}
      </div>
    );
  }

  // Sort spans by start offset
  const sorted = [...spans].sort((a, b) => a.start - b.start);

  // Build segments: alternate between normal text and highlighted text
  const segments: React.ReactNode[] = [];
  let lastEnd = 0;

  sorted.forEach((span, i) => {
    // Clamp offsets to body length
    const start = Math.max(0, Math.min(span.start, body.length));
    const end = Math.max(start, Math.min(span.end, body.length));

    // Normal text before this span
    if (start > lastEnd) {
      segments.push(
        <span key={`text-${i}`}>{body.slice(lastEnd, start)}</span>
      );
    }

    // Highlighted span
    const severityClass = `highlight-${span.severity}`;
    segments.push(
      <mark
        key={`mark-${i}`}
        className={`highlight-mark ${severityClass}`}
        aria-label={span.reason}
        title={`${span.severity.toUpperCase()}: ${span.reason}`}
        onClick={() => setActiveTooltip(activeTooltip === i ? null : i)}
        style={{ position: "relative" }}
      >
        {body.slice(start, end)}
        {activeTooltip === i && (
          <span className="highlight-tooltip">
            <strong style={{ textTransform: "uppercase" }}>{span.severity}</strong>: {span.reason}
          </span>
        )}
      </mark>
    );

    lastEnd = end;
  });

  // Remaining text after last span
  if (lastEnd < body.length) {
    segments.push(
      <span key="text-end">{body.slice(lastEnd)}</span>
    );
  }

  return (
    <div className="highlighted-body" role="region" aria-label="Email body with highlighted phishing indicators">
      {segments}
    </div>
  );
}
