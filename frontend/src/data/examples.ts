/**
 * AgenticPhishDetector — Example Emails Data
 *
 * 15 curated example emails covering phishing, legitimate, and suspicious
 * categories. Designed to exercise different combinations of agent tools.
 *
 * First 3 examples are designed to trigger ALL tools:
 *   - header_parser (sender domain mismatch / brand impersonation)
 *   - whois_tool (suspicious domains present for WHOIS lookup)
 *   - url_scan (URLs present for URLScan.io search)
 *   - heuristics (urgency keywords, credential harvesting, etc.)
 */

import type { Example } from "../types/api";

export const examples: Example[] = [
  // ═══════════════════════════════════════════════════
  // FIRST 3: Designed to trigger ALL 4 tools
  // ═══════════════════════════════════════════════════

  {
    id: 1,
    label: "PHISHING",
    description: "PayPal credential phishing — ALL tools triggered",
    sender_email: "PayPal Security <security-alert@paypa1-verify.com>",
    receiver_email: "john.doe@gmail.com",
    date_time: "2024-11-15T09:32:00Z",
    subject: "⚠️ Your PayPal Account Has Been Limited — Immediate Action Required",
    body: `Dear Valued PayPal Customer,

We have detected unusual activity on your PayPal account and have temporarily limited your access. For your protection, we require you to verify your identity immediately.

Please click the link below to restore full access to your account:

https://paypa1-verify.com/secure/restore-account?id=8472916385

You must complete verification within 24 hours or your account will be permanently suspended and all funds will be frozen.

Required information:
- Full legal name
- Social Security Number
- Credit card number linked to your account
- Account password

This is an automated security notification from PayPal, Inc.
Do not reply to this email.

PayPal Trust & Safety Department
San Jose, CA 95131`,
  },

  {
    id: 2,
    label: "PHISHING",
    description: "Amazon order scam with malicious URL — ALL tools triggered",
    sender_email: "Amazon.com <order-update@amaz0n-orders.net>",
    receiver_email: "sarah.williams@outlook.com",
    date_time: "2024-12-03T14:21:00Z",
    subject: "Your Amazon Order #112-4938271-6628401 Has Been Placed — Confirm or Cancel",
    body: `Hello Sarah,

A new order has been placed on your Amazon account for:

  MacBook Pro 16" M3 Max — $3,499.00
  Shipping to: 742 Evergreen Terrace, Springfield, IL 62704

If you did NOT place this order, you must cancel it immediately to avoid being charged:

https://amaz0n-orders.net/cancel-order/112-4938271

If you do not cancel within 2 hours, the order will be processed and your payment method will be charged.

For security purposes, you will be asked to verify your Amazon login credentials and payment information.

Thank you for shopping with Amazon.
Amazon Customer Service
P.O. Box 81226, Seattle, WA 98108`,
  },

  {
    id: 3,
    label: "LEGITIMATE",
    description: "Airline booking confirmation",
    sender_email: "bookings@united.com",
    receiver_email: "traveler@email.com",
    date_time: "2025-03-15T18:20:00Z",
    subject: "Booking Confirmation — UA1234 SFO→JFK March 20",
    body: `Thank you for your booking!

Confirmation Number: ABC123
Flight: United Airlines UA1234
Route: San Francisco (SFO) → New York (JFK)
Date: March 20, 2025
Departure: 8:00 AM PT
Arrival: 4:35 PM ET
Passenger: John Doe
Seat: 14A (Window)
Class: Economy Plus

You can manage your booking at united.com/manage or through the United app.

Remember to check in online 24 hours before departure.

Safe travels!
United Airlines`,
  },


  // ═══════════════════════════════════════════════════
  // PHISHING examples — various tool combinations
  // ═══════════════════════════════════════════════════

  {
    id: 4,
    label: "LEGITIMATE",
    description: "Body only — no metadata at all",
    sender_email: null,
    receiver_email: null,
    date_time: null,
    subject: null,
    body: `Hi team, just wanted to share a quick update on the Q1 roadmap. We've finalized the feature list for the next sprint and the engineering leads have signed off on the estimates. The kickoff meeting is scheduled for next Tuesday at 10am. Please review the shared document before then and come prepared with any questions or concerns. Looking forward to a productive quarter!`,
  },

  {
    id: 5,
    label: "PHISHING",
    description: "IRS tax refund scam — heuristics heavy, no URLs",
    sender_email: "refund@irs-notification.com",
    receiver_email: null,
    date_time: null,
    subject: "Your Federal Tax Refund is Ready — Verify Now",
    body: `INTERNAL REVENUE SERVICE
Tax Refund Notification

After the last annual calculations of your fiscal activity, we have determined that you are eligible to receive a tax refund of $2,847.50.

To claim your refund, you must verify your identity within 48 hours by providing:
- Full Social Security Number
- Date of birth
- Current mailing address
- Bank routing and account numbers

Failure to verify your identity will result in permanent forfeiture of your refund. This offer cannot be extended.

VERIFY YOUR IDENTITY BY REPLYING TO THIS EMAIL.

This is an automated notification from the IRS e-Filing system.
Internal Revenue Service, Washington D.C.`,
  },

  {
    id: 6,
    label: "PHISHING",
    description: "DHL package delivery with tracking URL",
    sender_email: "noreply@dhl-express-tracking.com",
    receiver_email: "customer@email.com",
    date_time: "2025-02-10T16:45:00Z",
    subject: "DHL: Delivery Attempt Failed — Reschedule Required",
    body: `Dear Customer,

We attempted to deliver your parcel (Tracking: DHL-8472916385) but were unable to complete delivery due to an incomplete address.

Your package is being held at our distribution center and will be returned to the sender within 5 business days if not claimed.

To reschedule delivery, please confirm your address and pay a small redelivery fee of $2.99:

https://dhl-express-tracking.com/reschedule/DHL-8472916385

If not claimed within 5 business days, the package will be returned to sender.

DHL Express Logistics
International Shipping Division`,
  },

  {
    id: 7,
    label: "PHISHING",
    description: "Crypto wallet seed phrase theft",
    sender_email: "support@metamask-wallet.io",
    receiver_email: null,
    date_time: null,
    subject: "URGENT: Your MetaMask Wallet Requires Immediate Verification",
    body: `MetaMask Security Alert

We have detected unauthorized access attempts on your MetaMask wallet from an unrecognized device in Eastern Europe.

Your digital assets may be at risk of theft. To secure your wallet, you must immediately verify your:

1. 12-word seed phrase
2. Private recovery key
3. Wallet password

WARNING: Failure to verify within 12 hours will result in permanent loss of access to your funds. We cannot recover your assets without this verification.

Reply to this email with your seed phrase to initiate the security protocol.

MetaMask Trust & Safety Team
ConsenSys Software Inc.`,
  },

  // ═══════════════════════════════════════════════════
  // LEGITIMATE examples — should return low risk
  // ═══════════════════════════════════════════════════

  {
    id: 8,
    label: "LEGITIMATE",
    description: "GitHub pull request notification",
    sender_email: "notifications@github.com",
    receiver_email: "dev@company.com",
    date_time: "2025-03-01T14:30:00Z",
    subject: "[user/repo] Fix memory leak in connection pool (#142)",
    body: `@contributor opened a pull request in user/repo:

Fix memory leak in connection pool (#142)

This PR fixes the connection pool memory leak reported in #138. The issue was caused by connections not being properly returned to the pool when exceptions occurred during query execution.

Changes:
- Added proper cleanup in the connection finalizer
- Added try/finally blocks around pool checkout/checkin
- Added 3 unit tests for connection lifecycle edge cases
- Updated documentation for connection management

Files changed: 4 (+127, -23)

Requested reviewers: @maintainer, @senior-dev

View it on GitHub: https://github.com/user/repo/pull/142
You are receiving this because you are subscribed to this thread.`,
  },

  {
    id: 9,
    label: "LEGITIMATE",
    description: "Google password reset — user-initiated",
    sender_email: "noreply@accounts.google.com",
    receiver_email: "user@gmail.com",
    date_time: "2025-01-12T10:05:00Z",
    subject: "Password reset request for your Google Account",
    body: `Hi,

We received a request to reset the password for your Google Account (user@gmail.com).

If you made this request, click the link below to reset your password:

https://accounts.google.com/signin/v2/challenge/pwd/reset

This link will expire in 24 hours.

If you didn't request a password reset, you can safely ignore this email. Your password won't be changed until you click the link above and create a new one.

For more information, visit the Google Account Help Center.

The Google Accounts Team`,
  },

  {
    id: 10,
    label: "LEGITIMATE",
    description: "Company internal newsletter",
    sender_email: "newsletter@company.com",
    receiver_email: "all-staff@company.com",
    date_time: "2025-02-28T09:00:00Z",
    subject: "Weekly Team Update — February 28, 2025",
    body: `Hi team,

Here's this week's roundup:

Product Updates:
- v3.2 shipped on Tuesday with the new dashboard redesign
- Mobile app beta testing begins next Monday
- Customer NPS score increased to 72 (up from 65)

Team News:
- Welcome to Alice Chen, our new Senior Engineer!
- Company all-hands is Thursday at 2pm PST
- Q1 planning documents are available on Confluence

Reminders:
- Performance reviews are due by March 7
- Don't forget to submit your expense reports

Have a great weekend!
— The Leadership Team`,
  },

  {
    id: 11,
    label: "PHISHING",
    description: "Microsoft 365 credential harvest — ALL tools triggered",
    sender_email: "Microsoft 365 Admin <admin@microsoft365-security.org>",
    receiver_email: "mark.johnson@company.com",
    date_time: "2025-01-20T08:15:00Z",
    subject: "ACTION REQUIRED: Your Microsoft 365 Password Expires in 4 Hours",
    body: `Microsoft 365 Security Center

Dear mark.johnson@company.com,

Your Microsoft 365 password is set to expire today at 12:15 PM EST. If you do not update your password, you will immediately lose access to:

  - Outlook Email
  - Microsoft Teams
  - OneDrive & SharePoint
  - All Office 365 applications

Click here to keep your current password:
https://microsoft365-security.org/password/keep-current

IMPORTANT: This link will expire in 4 hours. After expiration, your IT administrator will need to manually reset your credentials.

Do NOT share this email or forward it to anyone.

Microsoft 365 Security Team
Ref: MS-SEC-2025-0120-4829`,
  },


  {
    id: 12,
    label: "PHISHING",
    description: "Body only — minimal phishing with URL",
    sender_email: null,
    receiver_email: null,
    date_time: null,
    subject: null,
    body: `Your account has been compromised. Someone from Russia tried to access your account. Click here immediately to secure it: https://secure-account-verify.xyz/login. Enter your username and password to confirm your identity. If you don't act within 1 hour, we cannot guarantee the safety of your account.`,
  },
];
