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
        <p style={{ margin: "var(--space-sm) 0 0", opacity: 0.5, fontSize: "var(--text-xs)" }}>
          Developed by Parsa Farshadfar
        </p>
      </footer>
    </>
  );
}
