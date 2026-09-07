# Service: Analysis Engines (Layer 3)

## Purpose
Executes specialized threat analyzers:
1. **Header & Authentication Validation**:
   - SPF, DKIM, DMARC, ARC verification.
   - Hop-by-hop latency and origin IP geolocation check.
2. **URL & Domain Analysis**:
   - Domain age, typosquatting/punycode detection, redirect unshortening.
   - URL lexical analysis and heuristics.
3. **Content & NLP Analysis**:
   - Social engineering triggers, urgency detection, credential phishing intent.
   - Brand impersonation heuristics.
4. **Attachment Analysis**:
   - Magic bytes/MIME mismatch detection, macro extraction (OLE/VBA), suspicious executable headers.
