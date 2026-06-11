/**
 * AgenticPhishDetector — Application Entry Point
 *
 * Mounts the React app, imports fonts and global styles.
 */

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

// Font imports
import "@fontsource-variable/geist";
import "@fontsource/geist-mono";

// Global styles (order matters)
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/components.css";

import App from "./App";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
