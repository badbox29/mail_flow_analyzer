# Mail Flow Analyzer

A single-file forensic email analysis tool. Paste raw email headers and get a complete, plain-English breakdown of what happened to a message — where it went, who handled it, whether authentication passed, where delays occurred, whether anything looks like impersonation, and where to look if something went wrong.

Designed for mail administrators and technically capable users who need fast answers without decoding raw headers by hand.

#### Screenshot
![Screenshot](screenshot.png)

#### Live Demo
[https://badbox29.github.io/rescission/](https://badbox29.github.io/mail_flow_analyzer/)


---

## Features

### Message Analysis
- **Executive Summary** — sender, recipient, subject, date, delivery time, hop count, detected mail provider, detected third-party gateway, and auth result badges at a glance
- **Recommended Investigation Point** — single actionable callout identifying where to focus troubleshooting, with system-specific suggested checks; color-coded by urgency (green/blue/amber/red) and collapsed or expanded accordingly
- **Evidence classification** — findings tagged as Direct Evidence, Correlated Evidence, or Heuristic Inference

### Security Signals
A dedicated card runs a battery of checks on every message and surfaces only the ones that fire, each as an expandable row with a plain-English explanation and the values that triggered it:
- **Reply-To Mismatch** — Reply-To domain differs from the sender domain
- **Message-ID Anomaly** — missing Message-ID, or Message-ID domain differing from the From domain
- **Mail Loop Indicator** — reinjection loops and duplicate hostnames in the routing chain
- **TLS Downgrade** — connection dropped from TLS to plain SMTP mid-flight
- **Return-Path Alignment** — Return-Path domain differs from From (with ESP bounce-domain awareness)
- **SCL/BCL Mismatch** — Microsoft spam and bulk levels that disagree in telling ways
- **Recipient Change** — message redirected mid-delivery (mail flow rule, forward, distribution group, alias, or compliance redirect)
- **Display Name Spoofing** — display name references a trusted domain but the sender is external
- **VIP Name Spoofing** — display name matches a configured executive/VIP pattern but the sender is external (classic BEC)
- **Lookalike Domain** — sender domain closely resembles a trusted domain via edit distance or common substitution tricks (rn→m, hyphenation, TLD swaps)

The impersonation checks (display name, VIP, lookalike) are powered by the Security settings and only run when the relevant fields are configured.

### Message Journey Timeline
- Hops grouped into logical **delivery phases**: External Sending → Public Routing → Third-Party Mail Gateway → Internal Hand-off → Cloud Mail Filtering → Internal Routing → Mailbox Delivery → Delivery Outcome
- Plain-English story annotations distributed inline: per-hop callouts, per-phase notes, and a final delivery outcome
- Each hop card shows system identification, TLS status, delay pill, and percentage of total transit time
- Collapsible hop cards with full detail: source/destination hostnames, IP, protocol, TLS version, queue ID, timestamp, delay bar, and raw Received header
- **Delivery Outcome phase** — color-coded by delivery status (delivered / bounced / rejected / deferred / incomplete)
- Expand All / Collapse All controls

### Authentication Analysis
- **Authentication Summary** — SPF, DKIM, DMARC, ARC, and Microsoft CompAuth as click-to-expand rows with plain-English explanations written in terms of the *sender's domain*, not your mail system
- **Third-party gateway intelligence** — detects Proofpoint, Mimecast, Barracuda, Cisco ESA, and others; when a gateway is present, auth results are sourced from the gateway's pre-forward verification rather than the boundary server's re-check, with a clear explanation of why
- **Security Analysis** — sender authorization, TLS coverage, DMARC status, DKIM signature, originating IP, HELO hostname, spam verdict; each item includes a plain-English sub-note
- SPF softfail vs. hard fail distinction clearly explained; domain names surfaced throughout
- **CompAuth reason 405 handling** — recognizes on-premises hybrid delivery and explains why composite auth was skipped rather than flagging it as a failure

### Infrastructure Detection
- **Mail provider detection** — Microsoft Exchange Online, On-prem Exchange, On-prem Exchange / M365 Hybrid, Google Workspace, Amazon SES, and more
- **Hybrid Exchange detection** — identifies cross-tenant headers and on-prem routing to label hybrid environments correctly
- **Gateway detection** — hostname pattern matching plus vendor-specific header fingerprinting (X-Proofpoint-GUID, X-MC-Unique, X-Barracuda-Spam-Score, X-IronPort-AV, etc.)
- Supports multi-gateway topologies (e.g. Mimecast → Google Workspace, Proofpoint → Exchange Online)
- Recognizes your own on-prem servers and custom gateway hostnames when configured in Settings

### Microsoft-Specific Analysis
- SCL, BCL, PCL with plain-English verdicts
- Microsoft CompAuth with reason code explanation
- X-Forefront-Antispam-Report expandable detail
- Network Message ID

### Delivery Analysis
- Total delivery time, hop-by-hop delay bars, average hop delay
- Per-hop percentage of total transit time
- Delay classification: Normal / Minor / Warning / Critical

### Delivery Classification
- Automatically classifies headers as: Completed, Bounced / NDR, Rejected, Deferred, or Incomplete
- NDR/bounce detection via DSN headers (Content-Type: message/delivery-status, Action: failed, X-Failed-Recipients, Status: 5xx)
- Incomplete delivery path detection for sender-provided headers from failed sends

### Environment Settings
A tabbed settings area (persisted to browser localStorage):
- **Environment tab** — underlying mail platform (M365, Exchange Online Hybrid, Google Workspace, On-Prem Exchange, Other On-Prem MTA), on-prem server hostnames, hybrid connector FQDNs, and custom inbound/outbound filter hostnames
- **Security tab** — internal/owned domains, trusted sender domains, and VIP/executive name patterns that power the impersonation and lookalike detections
- **Import / Export tab** — download settings to a JSON file or copy to clipboard; import from a file or pasted JSON, with an option to apply immediately or review first
- Multi-entry fields are auto-expanding textareas for easy maintenance of long lists

### Reporting
- **Print / Export to PDF** — light-theme, print-optimized output via browser print dialog
- **Five report types:**
  - *Executive Summary* — identity block, auth status, most likely finding, investigation point
  - *Full Detail* — all sections
  - *Security Analysis* — authentication summary, security analysis, security signals, Microsoft verdicts
  - *Mail Journey* — full phased hop timeline with story callouts and delivery outcome
  - *Custom* — checkbox-selectable sections, all checked by default
- All report types include an unconditional message identity header (from/to/subject/date/provider/gateway/auth)
- Security Signals appear in reports as a compact one-line-per-signal summary
- Reports are light-themed regardless of app theme; interactive elements stripped

### Additional Tools
- **Raw Header Viewer** — collapsed by default, searchable with keyword highlighting, full copy button
- **Sanitized Sharing** — one-click redaction of email addresses, IPs, Message IDs, tenant IDs, and hostnames for safe sharing in support tickets or forums
- **Compare Mode** — paste two header sets and get a side-by-side diff of fields, authentication results, routing hops, and Microsoft verdicts
- **Dark / Light mode** — defaults to dark; full theme toggle
- **Additional Headers** — collapsed by default; expands to show all non-standard headers with tooltips on known vendor headers

---

## Usage

This is a single static HTML file — no build tools, no dependencies, no server required.

1. Open `index.html` in any modern browser
2. (Optional) Open **Settings** and configure your environment and organization domains for best results
3. Paste raw email headers into the input field
4. Click **Decode Headers**

To get raw headers from common mail clients:

| Client | How to get raw headers |
|---|---|
| Outlook (desktop) | Open message → File → Properties → Internet headers |
| Outlook Web | Open message → ··· menu → View → View message source |
| Gmail | Open message → ··· menu → Show original |
| Apple Mail | Open message → View → Message → All Headers (or Cmd+Shift+H) |
| Thunderbird | Open message → View → Message Source |

---

## Settings & Impersonation Detection

The impersonation and lookalike detections require organizational context to work and to avoid false positives. Configure them under **Settings → Security**:

- **Internal / Owned Domains** — the domains your organization owns and sends from. This is the baseline for lookalike detection and should always be filled in for best results.
- **Trusted Sender Domains** — known-good external domains (partners, vendors, ESPs). Treated as legitimate and never flagged.
- **VIP / Executive Names** — names or titles to watch for in display names (e.g. executives, "IT Support", "Helpdesk").

Each detection degrades gracefully — if a field is empty, that specific check simply doesn't run.

Settings can be exported to a JSON file and shared with teammates so everyone's tool recognizes the same environment, or moved between machines.

---

## Hosting

The file can be served from any static host — GitHub Pages, Cloudflare Pages, Netlify, or a local web server. No backend is required.

**GitHub Pages example:**
1. Push `index.html` to a repository
2. Go to Settings → Pages → Source → select branch
3. Access at `https://yourusername.github.io/yourrepo/`

---

## Supported Systems

### Third-Party Mail Gateways
Proofpoint, Mimecast, Barracuda, Cisco ESA / IronPort, Abnormal Security, Agari, Forcepoint, Sophos, Trend Micro, Symantec / MessageLabs

### Cloud Mail Platforms
Microsoft Exchange Online, Exchange Online Protection, Microsoft Defender for Office 365, Google Workspace / Gmail, Amazon SES, SendGrid, Mailgun

### On-Premises MTAs
Postfix, Exim, Sendmail, Microsoft Exchange Server

### Hybrid Topologies
Exchange Online + On-prem Exchange (M365 Hybrid), any gateway + any cloud platform combination

---

## Delivery Phase Definitions

| Phase | Description |
|---|---|
| External Sending | Origin server — first hop from the sender |
| Public Routing | Intermediate hops traversing public internet infrastructure |
| Third-Party Mail Gateway | Message scanned by a security gateway (Proofpoint, Mimecast, etc.) |
| Internal Hand-off | Gateway forwarding to the destination mail platform |
| Cloud Mail Filtering | EOP, Google Workspace inbound processing, or equivalent |
| Internal Routing | On-premises Exchange routing after cloud handoff |
| Mailbox Delivery | Final delivery to the recipient mailbox |
| Delivery Outcome | Verdict — delivered, bounced, rejected, deferred, or incomplete |

---

## Notes on Header Reliability

Headers added by servers the sender controls — typically the first one or two hops — can be forged. The most trustworthy headers are those stamped by servers your organization controls, generally the last few hops before delivery. The tool notes this in the interface.

When a third-party gateway is detected, authentication results shown throughout the tool reflect the gateway's pre-forward verification rather than the boundary server's re-check. The boundary re-check failures seen when mail flows through gateways like Proofpoint are a known artifact of that routing pattern and are not spoofing indicators.

---

## Privacy

All processing happens locally in your browser. Headers are never transmitted anywhere. Settings are stored only in your browser's localStorage and can be exported or cleared at any time.

---

## Version

v1.6

---

## License

See LICENSE file.
