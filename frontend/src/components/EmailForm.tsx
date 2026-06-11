/**
 * AgenticPhishDetector — EmailForm Component
 *
 * Email input form with 5 fields (sender, receiver, date, subject, body).
 * Only body is required. Includes live character counts, validation,
 * and submit/clear buttons.
 */

import { useState } from "react";
import { Send, Trash2, Loader2 } from "lucide-react";
import type { AnalyzeRequest } from "../types/api";

interface EmailFormProps {
  onSubmit: (data: AnalyzeRequest) => void;
  isLoading: boolean;
  onClear: () => void;
}

export function EmailForm({ onSubmit, isLoading, onClear }: EmailFormProps) {
  const [senderEmail, setSenderEmail] = useState("");
  const [receiverEmail, setReceiverEmail] = useState("");
  const [dateTime, setDateTime] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");

  const MAX_BODY = 50000;
  const MAX_SUBJECT = 500;

  /** Extract just the email address from formats like: Display Name <email@domain.com> */
  const extractEmail = (raw: string): string | null => {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    const match = trimmed.match(/<([^>]+)>/);
    return match ? match[1].trim() : trimmed;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (body.trim().length < 10) return;

    onSubmit({
      sender_email: extractEmail(senderEmail),
      receiver_email: extractEmail(receiverEmail),
      date_time: dateTime || null,
      subject: subject.trim() || null,
      body: body.trim(),
    });
  };

  const handleClear = () => {
    setSenderEmail("");
    setReceiverEmail("");
    setDateTime("");
    setSubject("");
    setBody("");
    onClear();
  };

  const fillExample = (data: AnalyzeRequest) => {
    setSenderEmail(data.sender_email || "");
    setReceiverEmail(data.receiver_email || "");
    setDateTime(data.date_time || "");
    setSubject(data.subject || "");
    setBody(data.body);
  };

  // Expose fillExample for parent components
  (window as any).__emailFormFill = fillExample;

  return (
    <form id="email-analysis-form" onSubmit={handleSubmit} className="card" style={{ marginBottom: "var(--space-xl)" }}>
      <h2 style={{ fontSize: "var(--text-lg)", marginBottom: "var(--space-lg)" }}>
        📧 Email to Analyze
      </h2>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "var(--space-md)" }}>
        {/* Sender Email */}
        <div className="form-group">
          <label className="form-label" htmlFor="sender-email">
            From (Sender)
            <span className="form-sublabel"> — optional</span>
          </label>
          <input
            id="sender-email"
            type="text"
            className="form-input"
            placeholder='e.g., "Amazon" <noreply@amazon-secure.xyz>'
            value={senderEmail}
            onChange={(e) => setSenderEmail(e.target.value)}
          />
        </div>

        {/* Receiver Email */}
        <div className="form-group">
          <label className="form-label" htmlFor="receiver-email">
            To (Receiver)
            <span className="form-sublabel"> — optional</span>
          </label>
          <input
            id="receiver-email"
            type="text"
            className="form-input"
            placeholder="e.g., victim@gmail.com"
            value={receiverEmail}
            onChange={(e) => setReceiverEmail(e.target.value)}
          />
        </div>

        {/* Date/Time */}
        <div className="form-group">
          <label className="form-label" htmlFor="email-datetime">
            Date & Time
            <span className="form-sublabel"> — optional</span>
          </label>
          <input
            id="email-datetime"
            type="datetime-local"
            className="form-input"
            value={dateTime}
            onChange={(e) => setDateTime(e.target.value)}
          />
        </div>

        {/* Subject */}
        <div className="form-group">
          <label className="form-label" htmlFor="email-subject">
            Subject
            <span className="form-sublabel"> — optional</span>
          </label>
          <input
            id="email-subject"
            type="text"
            className="form-input"
            placeholder="e.g., Important Security Update"
            value={subject}
            maxLength={MAX_SUBJECT}
            onChange={(e) => setSubject(e.target.value)}
          />
          <div className={`char-count ${subject.length > MAX_SUBJECT * 0.9 ? "warning" : ""}`}>
            {subject.length}/{MAX_SUBJECT}
          </div>
        </div>
      </div>

      {/* Body */}
      <div className="form-group" style={{ marginTop: "var(--space-md)" }}>
        <label className="form-label" htmlFor="email-body">
          Email Body
          <span className="form-sublabel"> — required (min 10 characters)</span>
        </label>
        <textarea
          id="email-body"
          className="form-textarea"
          placeholder="Paste the full email body here, including any raw headers if available..."
          value={body}
          maxLength={MAX_BODY}
          onChange={(e) => setBody(e.target.value)}
          required
          minLength={10}
          rows={8}
        />
        <div className={`char-count ${body.length > MAX_BODY * 0.9 ? "warning" : ""}`}>
          {body.length.toLocaleString()}/{MAX_BODY.toLocaleString()}
        </div>
      </div>

      {/* Buttons */}
      <div style={{ display: "flex", gap: "var(--space-md)", marginTop: "var(--space-lg)", justifyContent: "flex-end" }}>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={handleClear}
          disabled={isLoading}
          id="clear-form-btn"
        >
          <Trash2 size={16} />
          Clear
        </button>
        <button
          type="submit"
          className="btn btn-primary btn-lg"
          disabled={isLoading || body.trim().length < 10}
          id="analyze-btn"
        >
          {isLoading ? (
            <>
              <Loader2 size={18} className="spinner" style={{ animation: "spin 0.6s linear infinite" }} />
              Analyzing...
            </>
          ) : (
            <>
              <Send size={18} />
              Analyze Email
            </>
          )}
        </button>
      </div>
    </form>
  );
}
