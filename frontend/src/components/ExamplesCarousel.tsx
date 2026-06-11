/**
 * AgenticPhishDetector — ExamplesCarousel Component
 *
 * Horizontal scrollable carousel of 20 pre-loaded example emails.
 * Clicking an example autofills the EmailForm.
 */

import { examples } from "../data/examples";
import type { Example } from "../types/api";

interface ExamplesCarouselProps {
  onSelect: (example: Example) => void;
}

export function ExamplesCarousel({ onSelect }: ExamplesCarouselProps) {
  return (
    <div className="examples-section">
      <h3 style={{ fontSize: "var(--text-base)", marginBottom: "var(--space-sm)", color: "var(--color-text-muted)" }}>
        💡 Try an Example
      </h3>
      <div className="examples-scroll">
        {examples.map((ex) => {
          const labelColor =
            ex.label === "PHISHING"
              ? "var(--color-verdict-phishing)"
              : ex.label === "SUSPICIOUS"
              ? "var(--color-verdict-suspicious)"
              : "var(--color-verdict-legitimate)";

          return (
            <div
              key={ex.id}
              className="example-card"
              onClick={() => onSelect(ex)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === "Enter" && onSelect(ex)}
              id={`example-card-${ex.id}`}
            >
              <div className="example-card-label" style={{ color: labelColor }}>
                {ex.label}
              </div>
              <div className="example-card-desc">{ex.description}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
