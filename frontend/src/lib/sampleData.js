/**
 * Netra Cyber Threat Intelligence Sample Data & Case Archives
 * Grounded in SIH26106 forensic specifications.
 */

export const SAMPLE_BEC_EMAIL = `From: Security Desk <alert@micros0ft-support.com>
To: cfo-office@finance.org
Subject: Critical Security Notice: Reset Password Immediately
Date: Mon, 07 Sep 2026 14:32:00 +0000
Message-ID: <threat-case-0891@micros0ft-support.com>
Authentication-Results: mx.finance.org; spf=fail (IP 185.220.101.5); dkim=fail (body hash mismatch); dmarc=reject
Received: from mail.micros0ft-support.com ([185.220.101.5]) by mx.finance.org; Mon, 07 Sep 2026 14:32:01 +0000
Content-Type: text/plain; charset="UTF-8"

URGENT: Immediate executive action required!
Your corporate Microsoft 365 single sign-on credentials have expired or were flagged for suspicious activity.
Please verify your identity and confirm pending payment authorizations within 24 hours at:
https://secure-micros0ft-login.com/auth/login.php?user=cfo-office

Failure to authenticate will lead to executive tenant suspension.

Forensic Hash: 7f83b165249f0d361e2a0487103856b3e77f0a8246bc9e96194b1509a27e241
Corporate Security Operations Center`;

export const SAMPLE_INVOICE_EMAIL = `From: Accounts Payable <billing@overdue-vendorgroup.net>
To: finance-ops@finance.org
Subject: Overdue Wire Remittance: Invoice #INV-2026-994
Date: Mon, 07 Sep 2026 13:15:00 +0000
Message-ID: <invoice-994@overdue-vendorgroup.net>
Authentication-Results: mx.finance.org; spf=softfail; dkim=neutral; dmarc=none
Received: from gateway.fake-relay.org ([45.154.255.89]) by mx.finance.org

Dear Finance Team,

Please find attached the revised banking coordinates for pending wire settlement #INV-2026-994.
Due to our annual audit, our previous SWIFT routing is disabled.
Execute remittance via: http://45.154.255.89/wire-remittance/verify.html

Attachment: Invoice_Details_Confidential.pdf.exe
SHA-256: 4e91bc8201a4e58b1f23c91e0a816c7294bb80df3e028bfa17c0938472910fae

Regards,
Vendor Controller`;

export const SAMPLE_CASE_0891 = {
  caseId: "SEC-0891",
  rawId: "#0891",
  caseNumber: "Case #2026-0891: Financial BEC Impersonation",
  caseCode: "CASE #200-8841-B",
  date: "Today, 14:32",
  timestampUtc: "Today, 14:32 UTC",
  vaultId: "VX-889-ALPHA",
  status: "Quarantined",
  statusBadge: "Quarantined & Sealed",
  blockNumber: "19,402,118",
  consensusState: "Online",
  sha256: "8f4e2c18d45e7f22a106b3a099bc451b72e3518e90a0f443b2a0c710b190f84a",
  shaShort: "8f4e2c18d...b190f84a",
  custodyStamp: "#BLOCK-929011",
  custodyNetwork: "Polygon PoS",
  riskScore: 94,
  maxRiskScore: 100,
  confidence: "98.2%",
  verdict: "MALICIOUS",
  title: "Critical BEC & Spoofed Display Name",
  description: "Header relay mismatch with spoofed CFO sender identity detected. Outbound envelope domain violates SPF & DMARC policy.",
  
  kpis: {
    finalVerdict: {
      status: "MALICIOUS",
      confidence: "99.8%",
      level: "High Risk",
    },
    threatCategory: {
      category: "BEC Impersonation",
      subtype: "Payroll Wire Diversion",
      dkimResult: "FAIL",
    },
    containmentImpact: {
      status: "High / Blocked",
      targetMailbox: "cfo-office@finance.org",
      recipientsProtected: "1 / 1 Node",
    },
    pipelineLatency: {
      totalTime: "1.24s",
      nodesTraversed: "4 Relays",
      heuristicStatus: "Validated",
    }
  },

  authProtocols: {
    summary: "ALL CHECKS FAILED",
    checks: [
      {
        protocol: "SPF",
        details: "185.220.101.5",
        subtext: "Designated IP not listed in TXT record",
        status: "FAIL",
        statusType: "danger",
      },
      {
        protocol: "DKIM",
        details: "s=k1; d=executive-internal.net",
        subtext: "Signature body hash verification mismatch",
        status: "FAIL",
        statusType: "danger",
      },
      {
        protocol: "DMARC",
        details: "p=reject; sp=reject; aspf=r",
        subtext: "Strict quarantine override triggered",
        status: "REJECT",
        statusType: "danger",
      }
    ]
  },

  iocArtifacts: [
    {
      type: "IP",
      value: "185.220.101.5",
      badge: "AbuseIPDB 100%",
      badgeType: "danger",
      note: "Known Bulletproof / Tor Exit node",
    },
    {
      type: "DOMAIN",
      value: "secure-micros0ft-login.com",
      badge: "Age: 2 Days",
      badgeType: "warning",
      note: "Punycode & Typosquat registered 48h ago",
    },
    {
      type: "URL",
      value: "https://secure-micros0ft-login.com/auth/lo...",
      fullValue: "https://secure-micros0ft-login.com/auth/login.php?user=cfo-office",
      badge: "Credential Harvester",
      badgeType: "danger",
      note: "Phishing kit targeting O365 SSO",
    },
    {
      type: "SHA-256",
      value: "7f83b165...e241",
      fullValue: "7f83b165249f0d361e2a0487103856b3e77f0a8246bc9e96194b1509a27e241",
      badge: "Known Stealer",
      badgeType: "danger",
      note: "RedLine payload binary signature",
    }
  ],

  infrastructure: {
    location: "Frankfurt am Main",
    country: "DE",
    locationDetail: "Frankfurt, DE · Hetzner Cloud DC",
    confidence: "89% Confidence",
    networkProvider: "ASN 24940 (Hetzner Online GmbH)",
    roundtripLatency: "14ms · Trace Hop #4",
    disclaimer: "Intermediate relay infrastructure, not verified physical attacker location.",
    coordinates: { lat: 50.1109, lng: 8.6821 }
  },

  correlationGraph: {
    clusterId: "CLUSTER #APT-FIN26",
    mitreCode: "MITRE ATT&CK T1566.002",
    statusText: "Active Command-and-Control Linkage",
    nodes: [
      { id: "email", step: "01", type: "Email", label: "RFC-822", icon: "Mail" },
      { id: "fqdn", step: "02", type: "Spoof FQDN", label: "Micros0ft", icon: "Building" },
      { id: "relay", step: "03", type: "Relay IP", label: "185.220.*", icon: "Server" },
      { id: "auth", step: "04", type: "Auth URL", label: "/auth/login", icon: "Link" },
      { id: "payload", step: "05", type: "Payload", label: "Stealer Bin", icon: "Bug" },
    ]
  },

  relayHops: [
    {
      hopNumber: "HOP 01: ORIGIN",
      ip: "185.220.101.42",
      description: "Tor Exit / Frankfurt, DE",
      authStatus: "SPF FAIL",
      authType: "fail",
      latency: "0 ms (Source)",
      icon: "AlertTriangle",
      highlight: "danger",
    },
    {
      hopNumber: "HOP 02: PROXY",
      ip: "45.154.255.89",
      description: "MTA-Relay / Amsterdam, NL",
      authStatus: "DKIM VOID",
      authType: "fail",
      latency: "+142 ms",
      icon: "AlertCircle",
      highlight: "danger",
    },
    {
      hopNumber: "HOP 03: PERIMETER",
      ip: "142.250.185.27",
      description: "Cloud Gateway / London, UK",
      authStatus: "TLS 1.3 PASS",
      authType: "pass",
      latency: "+310 ms",
      icon: "ShieldCheck",
      highlight: "safe",
    },
    {
      hopNumber: "HOP 04: SINKHOLE",
      ip: "10.240.4.12",
      description: "200 OK Sandbox Vault",
      statusBadge: "QUARANTINE",
      authType: "quarantine",
      latency: "+788 ms",
      icon: "Lock",
      highlight: "quarantine",
    }
  ]
};

export const SAMPLE_CASE_0890 = {
  caseId: "SEC-0890",
  rawId: "#0890",
  caseNumber: "Case #2026-0890: Microsoft SSO Credential Harvesting",
  caseCode: "CASE #200-8839-A",
  date: "Yesterday, 19:14",
  timestampUtc: "Yesterday, 19:14 UTC",
  vaultId: "VX-872-BETA",
  status: "Blocked",
  statusBadge: "Blocked at Ingress",
  blockNumber: "19,401,902",
  consensusState: "Online",
  sha256: "c18d9f4e245e7f22a106b3a099bc451b72e3518e90a0f443b2a0c710b190a991",
  shaShort: "c18d9f4e2...b190a991",
  custodyStamp: "#BLOCK-928842",
  custodyNetwork: "Polygon PoS",
  riskScore: 88,
  maxRiskScore: 100,
  confidence: "95.6%",
  verdict: "MALICIOUS",
  title: "Typosquatted SSO Login Portal",
  description: "Domain age 48 hours mimicking corporate Microsoft 365 identity provider. Reverse proxy token interception detected.",
  kpis: {
    finalVerdict: {
      status: "MALICIOUS",
      confidence: "95.6%",
      level: "High Risk",
    },
    threatCategory: {
      category: "Credential Harvester",
      subtype: "Reverse Proxy Phish",
      dkimResult: "FAIL",
    },
    containmentImpact: {
      status: "High / Blocked",
      targetMailbox: "ops-lead@enterprise.net",
      recipientsProtected: "1 / 1 Node",
    },
    pipelineLatency: {
      totalTime: "1.18s",
      nodesTraversed: "3 Relays",
      heuristicStatus: "Validated",
    }
  },
  authProtocols: {
    summary: "AUTHENTICATION FAILED",
    checks: [
      { protocol: "SPF", details: "198.51.100.42", subtext: "Unauthorized IP relay", status: "FAIL", statusType: "danger" },
      { protocol: "DKIM", details: "d=micros0ft-support.com", subtext: "Cryptographic signature revoked", status: "FAIL", statusType: "danger" },
      { protocol: "DMARC", details: "p=reject", subtext: "Domain alignment rejected", status: "REJECT", statusType: "danger" },
    ]
  },
  iocArtifacts: [
    { type: "IP", value: "198.51.100.42", badge: "AbuseIPDB 96%", badgeType: "danger", note: "Hosting bulletproof reverse proxy" },
    { type: "DOMAIN", value: "micros0ft-support.com", badge: "Age: 1 Day", badgeType: "warning", note: "Homoglyph spoofing" },
    { type: "URL", value: "https://micros0ft-support.com/login", fullValue: "https://micros0ft-support.com/login", badge: "Phishing Kit", badgeType: "danger", note: "Evilginx2 proxy kit" },
    { type: "SHA-256", value: "9b3c4f...8921", fullValue: "9b3c4f245e7f22a106b3a099bc451b72e3518e90a0f443b2a0c710b1908921", badge: "Payload Drop", badgeType: "danger", note: "Injected script" },
  ],
  infrastructure: {
    location: "Amsterdam, Netherlands",
    country: "NL",
    locationDetail: "Amsterdam, NL · DigitalOcean DC",
    confidence: "92% Confidence",
    networkProvider: "ASN 14061 (DigitalOcean LLC)",
    roundtripLatency: "21ms · Trace Hop #3",
    disclaimer: "Cloud VM proxy endpoint, originating threat IP masked.",
    coordinates: { lat: 52.3676, lng: 4.9041 }
  },
  correlationGraph: {
    clusterId: "CLUSTER #APT-STORM08",
    mitreCode: "MITRE ATT&CK T1566.001",
    statusText: "Active Phishing Infrastructure",
    nodes: [
      { id: "email", step: "01", type: "Email", label: "O365 Alert", icon: "Mail" },
      { id: "fqdn", step: "02", type: "Spoof FQDN", label: "Micros0ft", icon: "Building" },
      { id: "relay", step: "03", type: "Relay IP", label: "198.51.*", icon: "Server" },
      { id: "auth", step: "04", type: "Auth URL", label: "/sso/login", icon: "Link" },
      { id: "payload", step: "05", type: "Payload", label: "Session Hijack", icon: "Bug" },
    ]
  },
  relayHops: [
    { hopNumber: "HOP 01: ORIGIN", ip: "198.51.100.42", description: "VPS Exit / Amsterdam, NL", authStatus: "SPF FAIL", authType: "fail", latency: "0 ms (Source)", icon: "AlertTriangle", highlight: "danger" },
    { hopNumber: "HOP 02: PROXY", ip: "104.244.42.1", description: "Cloudflare Edge", authStatus: "DKIM VOID", authType: "fail", latency: "+42 ms", icon: "AlertCircle", highlight: "danger" },
    { hopNumber: "HOP 03: PERIMETER", ip: "142.250.185.12", description: "Mail Gateway / Dublin, IE", authStatus: "TLS 1.3 PASS", authType: "pass", latency: "+110 ms", icon: "ShieldCheck", highlight: "safe" },
    { hopNumber: "HOP 04: SINKHOLE", ip: "10.240.4.15", description: "Netra Quarantine Sandbox", statusBadge: "BLOCKED", authType: "quarantine", latency: "+480 ms", icon: "Lock", highlight: "quarantine" },
  ]
};

export const SAMPLE_CASE_0889 = {
  caseId: "SEC-0889",
  rawId: "#0889",
  caseNumber: "Case #2026-0889: Weekly HR Engineering Digest",
  caseCode: "CASE #200-8830-C",
  date: "24 Oct, 09:05",
  timestampUtc: "24 Oct, 09:05 UTC",
  vaultId: "VX-860-GAMMA",
  status: "Delivered",
  statusBadge: "Clean & Verified",
  blockNumber: "19,398,401",
  consensusState: "Online",
  sha256: "089f4e2c18d45e7f22a106b3a099bc451b72e3518e90a0f443b2a0c710b190f8",
  shaShort: "089f4e2c1...0b190f8",
  custodyStamp: "#BLOCK-925102",
  custodyNetwork: "Polygon PoS",
  riskScore: 8,
  maxRiskScore: 100,
  confidence: "99.9%",
  verdict: "BENIGN",
  title: "Internal Corporate Communication",
  description: "All authentication checks passed with strict domain alignment. No malicious indicators found.",
  kpis: {
    finalVerdict: {
      status: "BENIGN",
      confidence: "99.9%",
      level: "Safe",
    },
    threatCategory: {
      category: "Benign Newsletter",
      subtype: "Internal Communication",
      dkimResult: "PASS",
    },
    containmentImpact: {
      status: "Delivered",
      targetMailbox: "hr-support@corp.internal",
      recipientsProtected: "0 Threatened",
    },
    pipelineLatency: {
      totalTime: "0.42s",
      nodesTraversed: "2 Relays",
      heuristicStatus: "Clean",
    }
  },
  authProtocols: {
    summary: "ALL CHECKS PASSED",
    checks: [
      { protocol: "SPF", details: "192.0.2.1", subtext: "Legitimate corporate MX", status: "PASS", statusType: "safe" },
      { protocol: "DKIM", details: "d=corp.internal", subtext: "Valid corporate signature", status: "PASS", statusType: "safe" },
      { protocol: "DMARC", details: "p=reject", subtext: "Strict alignment matched", status: "PASS", statusType: "safe" },
    ]
  },
  iocArtifacts: [
    { type: "IP", value: "192.0.2.1", badge: "Reputation Clean", badgeType: "safe", note: "Internal mail server" },
    { type: "DOMAIN", value: "corp.internal", badge: "Age: 5+ Years", badgeType: "safe", note: "Corporate domain" },
    { type: "URL", value: "https://intranet.corp.internal/digest", fullValue: "https://intranet.corp.internal/digest", badge: "Internal Portal", badgeType: "safe", note: "Corporate Intranet" },
    { type: "SHA-256", value: "e3b0c4...4298", fullValue: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", badge: "Signed Document", badgeType: "safe", note: "Clean PDF" },
  ],
  infrastructure: {
    location: "Bengaluru, India",
    country: "IN",
    locationDetail: "Bengaluru, IN · Internal Campus MX",
    confidence: "99% Confidence",
    networkProvider: "ASN 55836 (National Informatics Centre)",
    roundtripLatency: "4ms · Trace Hop #2",
    disclaimer: "Verified internal infrastructure.",
    coordinates: { lat: 12.9716, lng: 77.5946 }
  },
  correlationGraph: {
    clusterId: "CLUSTER #BENIGN-INTERNAL",
    mitreCode: "MITRE ATT&CK: None",
    statusText: "Trusted Internal Route",
    nodes: [
      { id: "email", step: "01", type: "Email", label: "Internal Digest", icon: "Mail" },
      { id: "fqdn", step: "02", type: "Domain", label: "corp.internal", icon: "Building" },
      { id: "relay", step: "03", type: "Mail Hub", label: "192.0.*", icon: "Server" },
      { id: "auth", step: "04", type: "Intranet", label: "/digest", icon: "Link" },
      { id: "payload", step: "05", type: "Status", label: "Delivered", icon: "ShieldCheck" },
    ]
  },
  relayHops: [
    { hopNumber: "HOP 01: ORIGIN", ip: "192.0.2.1", description: "Internal Mail Hub", authStatus: "SPF PASS", authType: "pass", latency: "0 ms", icon: "ShieldCheck", highlight: "safe" },
    { hopNumber: "HOP 02: GATEWAY", ip: "10.0.0.1", description: "Campus Perimeter Gateway", authStatus: "DKIM PASS", authType: "pass", latency: "+4 ms", icon: "ShieldCheck", highlight: "safe" },
    { hopNumber: "HOP 03: RECIPIENT", ip: "10.0.12.45", description: "End-user Exchange Mailbox", authStatus: "DELIVERED", authType: "pass", latency: "+8 ms", icon: "ShieldCheck", highlight: "safe" },
  ]
};

export const SAMPLE_CASE_0888 = {
  caseId: "SEC-0888",
  rawId: "#0888",
  caseNumber: "Case #2026-0888: Weaponized ISO Trojan Dropper",
  caseCode: "CASE #200-8822-D",
  date: "23 Oct, 18:41",
  timestampUtc: "23 Oct, 18:41 UTC",
  vaultId: "VX-855-DELTA",
  status: "Isolated",
  statusBadge: "Deep Isolated Vault",
  blockNumber: "19,395,210",
  consensusState: "Online",
  sha256: "96f4e2c18d45e7f22a106b3a099bc451b72e3518e90a0f443b2a0c710b190f896",
  shaShort: "96f4e2c18...0b190f896",
  custodyStamp: "#BLOCK-922119",
  custodyNetwork: "Polygon PoS",
  riskScore: 96,
  maxRiskScore: 100,
  confidence: "99.4%",
  verdict: "MALICIOUS",
  title: "Encapsulated Malicious ISO Attachment",
  description: "Double extension invoice document encapsulating LNK shortcut and DLL loader targeting DevOps administrative credentials.",
  kpis: {
    finalVerdict: {
      status: "MALICIOUS",
      confidence: "99.4%",
      level: "Critical Risk",
    },
    threatCategory: {
      category: "Trojan Dropper (ISO)",
      subtype: "DLL Search-Order Hijack",
      dkimResult: "FAIL",
    },
    containmentImpact: {
      status: "Isolated",
      targetMailbox: "dev-ops@cloudinfra.io",
      recipientsProtected: "1 / 1 Node",
    },
    pipelineLatency: {
      totalTime: "1.65s",
      nodesTraversed: "4 Relays",
      heuristicStatus: "Malware Detected",
    }
  },
  authProtocols: {
    summary: "ALL CHECKS FAILED",
    checks: [
      { protocol: "SPF", details: "91.240.118.12", subtext: "Unauthorized sender IP", status: "FAIL", statusType: "danger" },
      { protocol: "DKIM", details: "d=cloudinfra-support.org", subtext: "Signature invalid", status: "FAIL", statusType: "danger" },
      { protocol: "DMARC", details: "p=reject", subtext: "Quarantine enforced", status: "REJECT", statusType: "danger" },
    ]
  },
  iocArtifacts: [
    { type: "IP", value: "91.240.118.12", badge: "AbuseIPDB 100%", badgeType: "danger", note: "Bulletproof C2 host" },
    { type: "DOMAIN", value: "cloudinfra-support.org", badge: "Age: 3 Days", badgeType: "warning", note: "Spoofed infrastructure domain" },
    { type: "ATTACHMENT", value: "Release_v4.2.iso", fullValue: "Release_v4.2.iso", badge: "Weaponized Container", badgeType: "danger", note: "Contains malicious LNK & DLL" },
    { type: "SHA-256", value: "a4f89b...3182", fullValue: "a4f89b1298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b78523182", badge: "Trojan Payload", badgeType: "danger", note: "Qakbot variant loader" },
  ],
  infrastructure: {
    location: "Bucharest, Romania",
    country: "RO",
    locationDetail: "Bucharest, RO · Bulletproof C2 Gateway",
    confidence: "94% Confidence",
    networkProvider: "ASN 39351 (Voxility S.R.L.)",
    roundtripLatency: "28ms · Trace Hop #4",
    disclaimer: "Active command and control host identified in threat feeds.",
    coordinates: { lat: 44.4268, lng: 26.1025 }
  },
  correlationGraph: {
    clusterId: "CLUSTER #APT-TA570",
    mitreCode: "MITRE ATT&CK T1204.002",
    statusText: "Active C2 Linkage Identified",
    nodes: [
      { id: "email", step: "01", type: "Email", label: "DevOps Notice", icon: "Mail" },
      { id: "attach", step: "02", type: "Payload", label: "ISO Container", icon: "Bug" },
      { id: "relay", step: "03", type: "C2 IP", label: "91.240.*", icon: "Server" },
      { id: "loader", step: "04", type: "DLL Loader", label: "kernel32 hijack", icon: "Link" },
      { id: "stealer", step: "05", type: "Stealer", label: "Credential Drop", icon: "Bug" },
    ]
  },
  relayHops: [
    { hopNumber: "HOP 01: ORIGIN", ip: "91.240.118.12", description: "Bulletproof C2 / Bucharest, RO", authStatus: "SPF FAIL", authType: "fail", latency: "0 ms", icon: "AlertTriangle", highlight: "danger" },
    { hopNumber: "HOP 02: PROXY", ip: "185.190.140.22", description: "Fast-Flux Node", authStatus: "DKIM FAIL", authType: "fail", latency: "+54 ms", icon: "AlertCircle", highlight: "danger" },
    { hopNumber: "HOP 03: PERIMETER", ip: "142.250.180.20", description: "Border Gateway", authStatus: "TLS 1.3 PASS", authType: "pass", latency: "+180 ms", icon: "ShieldCheck", highlight: "safe" },
    { hopNumber: "HOP 04: SINKHOLE", ip: "10.240.4.99", description: "Malware Isolation Chamber", statusBadge: "ISOLATED", authType: "quarantine", latency: "+920 ms", icon: "Lock", highlight: "quarantine" },
  ]
};

export const CASES_MAP = {
  "#0891": SAMPLE_CASE_0891,
  "#0890": SAMPLE_CASE_0890,
  "#0889": SAMPLE_CASE_0889,
  "#0888": SAMPLE_CASE_0888,
};

export const INVESTIGATION_ARCHIVE = [
  {
    caseId: "#0891",
    date: "Today, 14:32",
    targetMailbox: "cfo-office@finance.org",
    detectedThreat: "BEC Impersonation",
    riskScore: "94 / 100",
    scoreNum: 94,
    status: "Quarantined",
    statusColor: "red",
    hasDot: true,
  },
  {
    caseId: "#0890",
    date: "Yesterday, 19:14",
    targetMailbox: "ops-lead@enterprise.net",
    detectedThreat: "Credential Harvester",
    riskScore: "88 / 100",
    scoreNum: 88,
    status: "Blocked",
    statusColor: "blue",
    hasDot: false,
  },
  {
    caseId: "#0889",
    date: "24 Oct, 09:05",
    targetMailbox: "hr-support@corp.internal",
    detectedThreat: "Benign Newsletter",
    riskScore: "08 / 100",
    scoreNum: 8,
    status: "Delivered",
    statusColor: "green",
    hasDot: false,
  },
  {
    caseId: "#0888",
    date: "23 Oct, 18:41",
    targetMailbox: "dev-ops@cloudinfra.io",
    detectedThreat: "Trojan Dropper (ISO)",
    riskScore: "96 / 100",
    scoreNum: 96,
    status: "Isolated",
    statusColor: "orange",
    hasDot: false,
  }
];

// NOTE: The pipeline stage list and its latencies are no longer hardcoded here.
// Stage definitions are served by the API Gateway (`/api/v1/pipeline/stages`) and
// per-stage latencies arrive as live events over SSE, measured by the service that
// performed the work. See `streamPipelineEvents` in lib/api.js.
