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
          background: "linear-gradient(90deg, var(--color-primary), #ff7eb3, #7e8cff)",
          WebkitBackgroundClip: "text",
          WebkitTextFillColor: "transparent",
          backgroundClip: "text",
          color: "transparent",
          textShadow: "0px 4px 15px rgba(255, 126, 179, 0.4)",
          letterSpacing: "1px",
          paddingTop: "var(--space-sm)"
        }}>
          Developed by Parsa Farshadfar
        </p>
      </footer>
    </>
  );
}
