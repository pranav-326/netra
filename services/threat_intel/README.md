# Service: Threat Intelligence Layer (Layer 5 & 10)

## Purpose
Enriches indicators of compromise (IOCs) using external feeds and intelligence providers:
- **IP Reputation**: AbuseIPDB, MaxMind GeoIP.
- **File Hashes**: VirusTotal, MalwareBazaar.
- **Domain & URLs**: URLhaus, WHOIS, DNSBLs.
- **Threat Exchange**: MISP integration.
- Caches IOC lookups in Redis to respect rate limits and reduce external latency.
