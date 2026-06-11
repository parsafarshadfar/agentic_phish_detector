/**
 * AgenticPhishDetector — ThemeToggle Component
 *
 * Toggles between light and dark themes by setting the data-theme
 * attribute on the document root. Persists preference to localStorage.
 * Animated Sun/Moon icon transition.
 */

import { useState, useEffect } from "react";
import { Sun, Moon } from "lucide-react";

export function ThemeToggle() {
  const [isDark, setIsDark] = useState(() => {
    const saved = localStorage.getItem("theme");
    if (saved) return saved === "dark";
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", isDark ? "dark" : "light");
    localStorage.setItem("theme", isDark ? "dark" : "light");
  }, [isDark]);

  return (
    <button
      id="theme-toggle"
      className="btn btn-secondary btn-sm"
      onClick={() => setIsDark(!isDark)}
      aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
      style={{ padding: "0.5rem" }}
    >
      {isDark ? (
        <Sun size={18} style={{ transition: "transform 0.3s ease", transform: "rotate(0deg)" }} />
      ) : (
        <Moon size={18} style={{ transition: "transform 0.3s ease", transform: "rotate(0deg)" }} />
      )}
    </button>
  );
}
