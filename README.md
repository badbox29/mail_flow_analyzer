# Mail Flow Analyzer

A single-file forensic email analysis tool. Paste raw email headers and get a complete, plain-English breakdown of what happened to a message — where it went, who handled it, whether authentication passed, where delays occurred, whether anything looks like impersonation, and where to look if something went wrong.

Designed for mail administrators and technically capable users who need fast answers without decoding raw headers by hand.

#### Screenshot
![Screenshot](screenshot.png)

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
- **Internal Domain Spoofing Suspected** — a message claims to be from one of your own internal domains and carries your mail platform's infrastructure fingerprint, but authentication was *evaluated and failed* and the message was *not* stamped as internal-origin by your organization — the signature of a foreign-tenant spoof (e.g. another Microsoft 365 customer sending as your domain)

The impersonation checks (display name, VIP, lookalike, internal-spoof) are powered by the Security settings and only run when the relevant fields are configured.

### Message Journey Timeline
- Hops grouped into logical **delivery phases**: External Sending → Public Routing → Third-Party Mail Gateway → Internal Hand-off → Cloud Mail Filtering → Internal Routing → Mailbox Delivery → Delivery Outcome
- Plain-English story annotations distributed inline: per-hop callouts, per-phase notes, and a final delivery outcome
- Each hop card shows system identification, TLS status, delay pill, and percentage of total transit time
- Collapsible hop cards with full detail: source/destination hostnames, IP, protocol, TLS version, queue ID, timestamp, delay bar, and raw Received header
- **Delivery Outcome phase** — color-coded by delivery status (delivered / bounced / rejected / deferred / incomplete)
- Expand All / Collapse All controls

### Authentication Analysis
- **Authentication Summary** — SPF, DKIM, DMARC, ARC, and Microsoft CompAuth as click-to-expand rows with plain-English explanations written in terms of the *sender's domain*, not your mail system
- **Evidence provenance** — each auth row shows *which header supplied the result* (boundary `Authentication-Results`, a gateway's `Authentication-Results-Original`, the ARC chain, `Received-SPF`, or a `DKIM-Signature`) and a collapsible view of the exact raw header line behind the verdict — so a finding can be verified or pasted as evidence
- **Third-party gateway intelligence** — detects Proofpoint, Mimecast, Barracuda, Cisco ESA, and others; when a gateway is present, auth results are sourced from the gateway's pre-forward verification rather than the boundary server's re-check, with a clear explanation of why
- **Origin-pass reframing** — when a check fails at the boundary but the gateway's original result or the ARC chain shows it passed at the message's origin, the row explains the failure as a forwarding/gateway artifact rather than a sender misconfiguration (e.g. a signature-appliance that broke DKIM in transit)
- **Internal-origin awareness** — mail that originated inside your organization (stamped `AuthAs: Internal` / `DIR:INT` / `Originating`, from one of your configured internal domains) is recognized across the Authentication Summary, Security Analysis, Mail Flow Story, and Investigation Point. Absent SPF/DKIM/DMARC results on such mail are correctly described as "not evaluated — internal-origin mail" rather than being flagged as a configuration gap
- **PermError / TempError fidelity** — SPF and DMARC `permerror` and `temperror` are shown as distinct states (not flattened to "none"), each explained; SPF permerror notes the common RFC 7208 >10-lookup cause
- **Honest DNS limits** — without live DNS lookups enabled, the tool never claims a domain "has no record" from header absence alone; it reports only what the message carried and says so
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
- **Quarantine-hold recognition** — a delay over one hour combined with authentication failures (especially a DMARC quarantine/reject disposition) is reframed as a likely quarantine hold with later release rather than a mail-transit delay, stated as an inference with the threshold and reasoning shown rather than as a certainty

### Delivery Classification
- Automatically classifies headers as: Completed, Bounced / NDR, Rejected, Deferred, or Incomplete
- Incomplete delivery path detection for sender-provided headers from failed sends
- Pasted bounce messages are auto-detected and routed to the full Bounce / NDR analysis engine (see the dedicated section below)

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
- **Bounce reports** — when a bounce is analyzed, reports include a Bounce / NDR section (verdict, failed recipients, codes, servers, suggested actions); a bounce-only paste produces a focused bounce report
- Reports are light-themed regardless of app theme; interactive elements stripped

### Additional Tools
- **Copy Summary** — generates a clean, paste-ready plain-text diagnostic summary for vendor emails or tickets. Context-aware: a normal message produces an identity + authentication (with provenance) + routing + key-findings block; a bounce produces a bounce-focused summary (verdict, codes, failed recipients, suggested actions). Includes published-DNS findings when DNS lookups are enabled
- **Malformed-header warning** — detects signs that pasted headers were reformatted or truncated in transit (unbracketed Message-IDs or `for` clauses, missing timestamps) and shows a non-alarming banner advising a fresh re-pull, so degraded input isn't silently trusted
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

### Bounce / NDR Formats
Microsoft 365 / Exchange, Sendmail / Proofpoint (human-readable), RFC 3464 (structured DSN)

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

All processing happens locally in your browser. Headers are never transmitted anywhere. Settings are stored only in your browser's localStorage and can be exported or cleared at any time. (The only exception is the optional Live DNS Lookups feature below, which is off by default and, when enabled, sends only the analyzed domain names to your chosen DNS provider.)

---

## Bounce / NDR Analysis

Paste a bounce message (non-delivery report) and the tool automatically detects it and switches to a dedicated bounce-analysis view instead of the normal delivery timeline. No mode toggle is needed.

### Formats detected
- **Microsoft 365 / Exchange** — the "Delivery has failed… / Diagnostic information for administrators" format
- **Sendmail / Proofpoint** — the human-readable "permanent fatal errors / Transcript of session" format
- **RFC 3464** — the structured `message/delivery-status` DSN format

All three are normalized into a single bounce model, so the display and logic are consistent regardless of source.

### What it extracts and explains
- **Severity verdict** — permanent, temporary, or expired-after-retries, color-coded
- **Failure classification** — DMARC failure, SPF failure, recipient-not-found, security/policy block, connection/target-host failure, message expired, mailbox full/quota, delivery restriction, or mail loop
- **Failed recipients** — handles multiple recipients in one NDR, and rejects message-IDs that look like addresses so they aren't mistaken for recipients
- **SMTP + enhanced status codes** — a built-in reference for common enhanced codes (e.g. `5.7.509` DMARC, `5.1.10` recipient-not-found, `5.4.300` expired) and Exchange RESOLVER tokens, surfaced as plain-English explanations
- **Cascading code chains** — chains like `550 5.4.300 → 451 4.4.397 → 421 4.4.2` are parsed and explained root-cause-first, labeling the ROOT CAUSE and FINAL OUTCOME
- **Contextual interpretation** — when a diagnostic names a specific cause (e.g. "hop count exceeded / mail loop") that interpretation takes precedence over the generic code meaning, with a context note
- **Attempt history** — timestamped retries when the NDR records multiple delivery attempts
- **Reporting vs. rejecting server** — labeled internal/external using your configured environment, so you can see whether the failure happened inside your own mail system or at an external party
- **Settings-aware suggested actions** — remediation steps tailored to the failure class *and* your environment. For a mail loop in an Exchange Online Hybrid setup, this includes the three most common hybrid causes: Exchange Online license status, the on-premises remote routing address, and mailbox identity/GUID consistency between on-prem and cloud
- **URLDefense unwrapping** — Proofpoint URL Defense links in diagnostics are unwrapped to the real destination, and URLs are made clickable
- **Collapsible SMTP/NDR code reference** — the relevant codes for this bounce plus common ones, available on demand

### Split / partial delivery
When a bounce includes the original message headers, the tool reconstructs per-recipient status by comparing the NDR's failed recipients against the original To/Cc. It clearly separates **failed** recipients from **delivered** (only when the NDR explicitly confirms it) and **not-reported-failed** recipients, and never claims blanket success for a message that bounced for some recipients. The embedded original-message analysis's Delivery Outcome becomes recipient-specific in this case.

### Embedded original-message analysis
If the bounce contains the original message's headers, that message is run through the full analysis engine (journey, phases, authentication, security signals) and rendered below the bounce verdict — so you get both why it bounced and the complete forensic picture of the message that bounced.

---

## Live DNS Lookups (optional)

By default the tool analyzes only the headers you paste and makes no network requests. You can optionally enable **live DNS lookups** so it also resolves the sender domain's actual published SPF, DKIM, and DMARC records and shows them in a "Published DNS Records" section. This confirms authentication findings against real DNS instead of only inferring from headers — for example, it can definitively show that a domain's SPF record exceeds the RFC 7208 10-lookup limit (the common cause of SPF permerror).

Enable it under **Settings → Live DNS Lookups**. Because it sends the analyzed domain names to a DNS provider, it is off by default. When enabled, lookups run automatically on each analysis. Three provider options:

- **Cloudflare DoH / Google DoH** — direct DNS-over-HTTPS from the browser, no setup. Retrieves the published records but does not perform recursive SPF include-chain expansion.
- **Custom Worker** — unlocks recursive SPF expansion with exact RFC 7208 lookup counting (needed to detect the "more than 10 lookups" permerror cause). Requires deploying the included Worker.

### What it shows
- **SPF lookup breakdown** — a clean numbered "ledger" of every lookup-consuming mechanism in evaluation order, with a running count, nesting for included records, and an explicit marker at the point the 10-lookup limit is crossed (mechanisms past it are never evaluated). The full record tree with IP ranges is available behind a collapsed expander.
- **Sender-authorization correlation** — when a lookup-consuming mechanism that falls *past* the limit belongs to the sending server's own domain, the tool notes that the mechanism which would authorize the sender is never reached — pinpointing exactly why an otherwise-legitimate sender fails SPF, and whose configuration needs to change.
- **DMARC** — the published policy (`p=`), subdomain policy, and percentage, with a plain-English note.
- **DKIM** — resolves the selector from the message's DKIM-Signature when present, or probes common selectors (Microsoft, Google, Mailchimp, etc.) via the Worker; shows which selectors are published or revoked.

### Integration with the rest of the analysis
When DNS confirms an SPF lookup-limit overflow, the finding is surfaced *above* the Published DNS Records section too: a headline banner at the top of the results, an upgrade to the Authentication Summary SPF row (from "likely a record problem, can't confirm without DNS" to the confirmed cause), and a line in the Copy Summary output — so the confirmed, DNS-backed conclusion travels into a report or vendor email.

### Deploying the DNS Worker

The repository includes `worker.js`, a self-contained Cloudflare Worker:

1. Create a new Worker in the Cloudflare dashboard (or `wrangler init`).
2. Paste `worker.js` as the Worker script and deploy.
3. Copy the Worker URL (e.g. `https://mfa-dns.yourname.workers.dev`).
4. In the tool: Settings → Live DNS Lookups → enable, choose **Custom Worker**, paste the URL. (Entering a URL auto-selects the Custom Worker provider, and a bare hostname is normalized to `https://` automatically.)

The Worker is stateless, needs no bindings or secrets, uses Cloudflare's edge cache, and stores nothing.

**Restricting access (optional):** set an `ALLOWED_ORIGINS` environment variable (Worker → Settings → Variables) to a comma-separated list of origins permitted to call the Worker, e.g. `https://yourname.github.io, https://tool.example.com`. The Worker echoes back a request's origin only if it's in the list (how browsers enforce the allowlist); other origins get a 403. If `ALLOWED_ORIGINS` is unset, empty, or contains `*`, the Worker allows any origin. Direct hits with no Origin header (opening the URL in a browser tab for testing) are always allowed.

A quick way to confirm the Worker is live after deploying: open `https://your-worker.workers.dev/?domain=example.com` in a browser — you should get JSON with the SPF/DMARC/DKIM breakdown.

---

## Testing

A Node-based regression test harness (`test-harness.js`) validates the parsing and analysis logic without a browser. It extracts the script from `index.html`, runs it in a sandboxed VM context, and asserts on the output of the core functions — header parsing, IP extraction (including hyphenated-PTR cases), gateway/system classification, internal-origin awareness, the internal-domain-spoofing discrimination, recipient-change multi-recipient handling, origin-pass reframing, authentication provenance, PermError fidelity, the full NDR/bounce engine (all three formats, code chains, mail-loop and hybrid remediation), and the copyable summary.

```
node test-harness.js                 # run against ./index.html
node test-harness.js path/to.html    # run against a specific build
```

It exits 0 if all tests pass and 1 if any fail, so it can be wired into a pre-commit hook or CI step. Fixtures are inline and self-contained. Add new cases to the `TESTS` array as functionality grows.

---

## Version

v1.8

---

## License

See LICENSE file.
