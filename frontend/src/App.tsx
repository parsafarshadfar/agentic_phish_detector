/**
 * AgenticPhishDetector — App Shell
 *
 * Root application component with navbar, theme toggle, and single page route.
 */

import { Shield } from "lucide-react";
import { ThemeToggle } from "./components/ThemeToggle";
import { DetectorPage } from "./pages/DetectorPage";

export default function App() {
  return (
    <>
      {/* Navbar */}
      <nav className="nav">
        <div className="nav-brand">
          <Shield size={20} style={{ color: "var(--color-primary)" }} />
          AgenticPhishDetector
        </div>

        <div className="nav-links">
          <ThemeToggle />
        </div>
      </nav>

      {/* Main Content */}
      <DetectorPage />

      {/* Footer */}
      <footer className="footer">
        <p style={{ margin: 0 }}>
          AgenticPhishDetector — Powered by LangGraph + NVIDIA Nemotron
        </p>
        <p style={{ margin: "var(--space-xs) 0 0", opacity: 0.7 }}>
          Emails submitted for analysis are not stored or used for training.
        </p>
        <p style={{
          margin: "var(--space-md) 0 0",
          fontSize: "var(--text-2xl)",
          fontWeight: "900",
          background: "linear-gradient(90deg, #1e40af, #3b82f6, #60a5fa)",
          WebkitBackgroundClip: "text",
          WebkitTextFillColor: "transparent",
          backgroundClip: "text",
          color: "transparent",
          textShadow: "0px 4px 15px rgba(59, 130, 246, 0.4)",
          letterSpacing: "1px",
          paddingTop: "var(--space-sm)"
        }}>
          Developed by Parsa Farshadfar
        </p>
        <a
          href="https://parsafarshadfar.com"
          target="_blank"
          rel="noopener noreferrer"
          style={{
            display: "inline-block",
            marginTop: "8px",
            fontSize: "1.1rem",
            fontWeight: "600",
            color: "#60a5fa",
            textDecoration: "none",
            letterSpacing: "0.5px",
            textShadow: "0px 2px 10px rgba(96, 165, 250, 0.3)"
          }}
        >
          parsafarshadfar.com
        </a>
      </footer>
    </>
  );
}
