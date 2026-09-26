'use client';

import React, { useState, useEffect, Suspense } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  Shield,
  ShieldAlert,
  AlertOctagon,
  Copy,
  Check,
  Download,
  ArrowRight,
  MapPin,
  Share2,
  Lock,
  ExternalLink,
  Code,
  Info,
  Network,
  Mail,
  Building,
  Server,
  Link as LinkIcon,
  Bug,
  X,
  FileDown,
  Loader2,
  AlertTriangle
} from 'lucide-react';
import { SAMPLE_CASE_0891, CASES_MAP } from '@/lib/sampleData';
import { fetchReportDetails, pollReportDetails, resolveIpGeolocation } from '@/lib/api';
import { transformBackendReport } from '@/lib/emlParser';
import ScoreWaterfall from '@/components/ScoreWaterfall';
import OriginClues from '@/components/OriginClues';

function ResultContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [caseData, setCaseData] = useState(SAMPLE_CASE_0891);
  // 'live'   = scored by the backend threat_engine for this email,
  // 'sample' = a bundled archive case browsed from the investigations list.
  // There is no third source: every score shown on this page came from the backend.
  const [provenance, setProvenance] = useState('sample');
  const [loadError, setLoadError] = useState(null);
  const [copiedKey, setCopiedKey] = useState(null);
  const [showJsonModal, setShowJsonModal] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [isLoadingLive, setIsLoadingLive] = useState(false);
  const [geoInfo, setGeoInfo] = useState(null);
  const [isLoadingGeo, setIsLoadingGeo] = useState(false);

  useEffect(() => {
    setLoadError(null);

    // 1. A backend email id is authoritative: fetch the real persisted report.
    //    If it never arrives we surface the failure rather than substituting a sample.
    const emailId = searchParams.get('id') || searchParams.get('email_id');
    if (emailId) {
      setIsLoadingLive(true);
      pollReportDetails(emailId, 20, 500).then((res) => {
        setIsLoadingLive(false);

        if (!res) {
          setLoadError(
            `No persisted report found for email ${emailId}. The pipeline accepted the email but ` +
            `the report has not reached PostgreSQL. Check the analyzer, threat_engine, and ` +
            `api_gateway container logs.`
          );
          return;
        }

        const transformed = transformBackendReport(res);
        if (!transformed) {
          setLoadError(`Backend returned a report for ${emailId} that could not be rendered.`);
          return;
        }

        transformed.backendEmailId = emailId;
        setCaseData(transformed);
        setProvenance('live');
      });
      return;
    }

    // 2. A bundled archive case, browsed directly from the investigations list.
    //    These are stored demonstrations, labelled as such — never a live verdict.
    const caseParam = searchParams.get('caseId') || searchParams.get('case');
    if (caseParam && CASES_MAP[caseParam]) {
      setCaseData(CASES_MAP[caseParam]);
      setProvenance('sample');
    }
  }, [searchParams]);

  // Dynamically resolve Real-World GeoIP, Country, and ASN for detected Ingress IP.
  // Guarded against two races: resolving against the placeholder sample case while the
  // live report is still in flight, and a slow lookup from a previous case landing after
  // the user has moved on to a new one.
  useEffect(() => {
    if (!caseData || isLoadingLive) return;

    let cancelled = false;
    setGeoInfo(null);

    // 1. Locate IP from IOC artifacts
    const ipArtifact = caseData.iocArtifacts?.find(i => (i.type || '').toUpperCase() === 'IP');
    let targetIp = ipArtifact?.value;

    // 2. The relay IP the report recorded
    if (!targetIp && caseData.infrastructure?.relayIp) {
      targetIp = caseData.infrastructure.relayIp;
    }

    // 3. Locate from first relay hop
    if (!targetIp && caseData.relayHops?.length > 0) {
      const match = caseData.relayHops[0].ip?.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
      if (match) targetIp = match[0];
    }

    if (targetIp && /^[0-9.]+$/.test(targetIp)) {
      setIsLoadingGeo(true);
      resolveIpGeolocation(targetIp).then(geo => {
        if (cancelled) return;
        setIsLoadingGeo(false);
        if (geo) {
          setGeoInfo(geo);
        }
      });
    }

    return () => { cancelled = true; };
  }, [caseData, isLoadingLive]);

  const handleCopy = (key, text) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(caseData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `netra-case-${caseData.caseId}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">

      {/* Provenance banner — states plainly where this report came from */}
      {isLoadingLive && (
        <div className="rounded-xl border border-blue-200 dark:border-blue-900 bg-blue-50 dark:bg-blue-950/40 p-3 flex items-center gap-3 text-xs text-blue-900 dark:text-blue-200">
          <Loader2 className="w-4 h-4 animate-spin shrink-0" />
          <span className="font-medium">Fetching the persisted report from the API Gateway…</span>
        </div>
      )}

      {loadError && (
        <div className="rounded-xl border border-red-300 dark:border-red-900 bg-red-50 dark:bg-red-950/40 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
          <div className="text-xs text-red-900 dark:text-red-200 space-y-1">
            <div className="font-bold">Live report unavailable</div>
            <p className="font-mono break-words">{loadError}</p>
            <p className="opacity-80">
              The report shown below is a bundled sample case, not the email you submitted.
            </p>
          </div>
        </div>
      )}

      {!isLoadingLive && !loadError && provenance !== 'live' && (
        <div className="rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 p-3 flex items-start gap-3 text-xs text-amber-900 dark:text-amber-200">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            <span className="font-bold">Bundled sample case.</span>{' '}
            An archived demonstration, not a live pipeline result. Submit an email from the
            analysis page to get a scored report.
          </div>
        </div>
      )}

      {provenance === 'live' && (
        <div className="rounded-xl border border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 p-3 flex items-center gap-3 text-xs text-emerald-900 dark:text-emerald-200">
          <Shield className="w-4 h-4 shrink-0" />
          <span>
            <span className="font-bold">Live pipeline report.</span>{' '}
            Scored by the threat_engine service and read back from PostgreSQL
            <span className="font-mono"> · email_id: {caseData.backendEmailId}</span>
          </span>
        </div>
      )}

      {/* Top Threat Summary Banner */}
      <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-6">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          
          {/* Left: Gauge & Details */}
          <div className="flex items-start gap-5">
            
            {/* Circular Risk Score Gauge */}
            <div className="relative w-20 h-20 shrink-0 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-slate-100 dark:text-slate-800 stroke-current"
                  strokeWidth="3.2"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className={`stroke-current stroke-round ${
                    caseData.riskScore >= 75 ? 'text-red-500' :
                    caseData.riskScore >= 45 ? 'text-amber-500' :
                    'text-emerald-500'
                  }`}
                  strokeWidth="3.2"
                  strokeDasharray={`${caseData.riskScore}, 100`}
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute flex flex-col items-center justify-center text-center">
                <span className={`text-xl font-black font-mono leading-none ${
                  caseData.riskScore >= 75 ? 'text-red-600 dark:text-red-500' :
                  caseData.riskScore >= 45 ? 'text-amber-600 dark:text-amber-500' :
                  'text-emerald-600 dark:text-emerald-500'
                }`}>
                  {caseData.riskScore}
                </span>
                <span className="text-[9px] font-mono text-slate-400 dark:text-slate-500 mt-0.5">
                  /100
                </span>
              </div>
            </div>

            {/* Verdict Meta & Headline */}
            <div className="space-y-2">
              <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full font-bold border ${
                  caseData.verdict === 'MALICIOUS'
                    ? 'bg-red-100 dark:bg-red-950/70 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800/60'
                    : caseData.verdict === 'SUSPICIOUS'
                    ? 'bg-amber-100 dark:bg-amber-950/70 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800/60'
                    : 'bg-emerald-100 dark:bg-emerald-950/70 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/60'
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${
                    caseData.verdict === 'MALICIOUS' ? 'bg-red-600 animate-pulse' :
                    caseData.verdict === 'SUSPICIOUS' ? 'bg-amber-600' :
                    'bg-emerald-600'
                  }`}></span>
                  {caseData.verdict}
                </span>
                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 font-semibold border border-blue-200/60 dark:border-blue-800">
                  <Shield className="w-3 h-3 text-blue-600" />
                  {caseData.confidence} Confidence
                </span>
                <span className="px-2.5 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold border border-slate-200 dark:border-slate-700">
                  {caseData.caseCode}
                </span>
              </div>

              <h1 className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-white">
                {caseData.title}
              </h1>

              <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 max-w-3xl leading-relaxed">
                {caseData.description}
              </p>
            </div>
          </div>

          {/* Right Action Buttons */}
          <div className="flex items-center gap-3 shrink-0 w-full lg:w-auto justify-end">
            <button
              onClick={() => setShowJsonModal(true)}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700 text-xs font-semibold shadow-xs transition"
            >
              <Code className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>

            <Link
              href="/report"
              className="inline-flex items-center gap-2 px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-md shadow-blue-500/20 transition"
            >
              <span>View Forensic Report</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

        </div>
      </div>

      {/* Score explainability — the rules that summed to this verdict */}
      <ScoreWaterfall
        contributions={caseData.ruleContributions}
        finalScore={caseData.riskScore}
        rawScore={caseData.scoreBeforeClamp}
        verdict={caseData.verdict}
      />

      {/* Two Column Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* ========================================================= */}
        {/* LEFT COLUMN: AUTH PROTOCOLS & IOC ARTIFACTS */}
        {/* ========================================================= */}
        <div className="space-y-6">
          
          {/* Card 1: Authentication Protocols */}
          <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-slate-700 dark:text-slate-300" />
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  Authentication Protocols
                </h2>
              </div>
              <span className="text-[11px] font-mono font-bold text-red-600 dark:text-red-400">
                {caseData?.authProtocols?.summary || 'SECURITY CHECK'}
              </span>
            </div>

            <div className="space-y-3 font-mono text-xs">
              {(caseData?.authProtocols?.checks || []).map((check, idx) => (
                <div
                  key={idx}
                  className="flex items-start justify-between p-2.5 rounded-lg bg-slate-50/70 dark:bg-slate-850 border border-slate-200/50 dark:border-slate-800/80"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2 font-semibold">
                      <span className="w-12 text-slate-800 dark:text-slate-200">{check.protocol}</span>
                      <span className="text-slate-700 dark:text-slate-300">{check.details}</span>
                    </div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {check.subtext}
                    </div>
                  </div>

                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    check.status === 'FAIL' || check.status === 'REJECT'
                      ? 'bg-red-100 dark:bg-red-950/80 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900/50'
                      : 'bg-emerald-100 text-emerald-600'
                  }`}>
                    {check.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Card 2: Extracted IOC Artifacts */}
          <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Share2 className="w-4 h-4 text-slate-700 dark:text-slate-300" />
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  Extracted IOC Artifacts
                </h2>
              </div>
              <span className="text-[11px] text-slate-400 font-mono">
                Click artifact to copy
              </span>
            </div>

            <div className="space-y-2.5 font-mono text-xs">
              {(caseData?.iocArtifacts || []).map((ioc, idx) => (
                <div
                  key={idx}
                  onClick={() => handleCopy(ioc.type, ioc.fullValue || ioc.value)}
                  className="group flex items-center justify-between p-2.5 rounded-lg bg-slate-50/70 dark:bg-slate-850 border border-slate-200/50 dark:border-slate-800/80 hover:border-blue-300 dark:hover:border-blue-700 cursor-pointer transition"
                >
                  <div className="flex items-center gap-3 truncate">
                    <span className="w-14 text-slate-400 dark:text-slate-500 font-semibold text-[11px]">
                      {ioc.type}
                    </span>
                    <span className="text-slate-800 dark:text-slate-200 truncate group-hover:text-blue-600 dark:group-hover:text-blue-400 transition">
                      {ioc.value}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded ${
                      ioc.badgeType === 'danger'
                        ? 'bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900/50'
                        : 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-900/50'
                    }`}>
                      {ioc.badge}
                    </span>
                    <button className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1">
                      {copiedKey === ioc.type ? (
                        <Check className="w-3.5 h-3.5 text-emerald-500" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* Bottom Proof Bar */}
            <div className="pt-2 flex items-center justify-between text-[11px] font-mono text-slate-500 dark:text-slate-400 border-t border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-1.5 text-blue-600 dark:text-blue-400 font-semibold">
                <Lock className="w-3 h-3" />
                <span>Chain of Custody Stamp: {caseData?.custodyStamp || '#BLOCK-NETRA'}</span>
              </div>
              <span className="text-slate-400">Immutable Proof Anchored</span>
            </div>
          </div>

        </div>

        {/* ========================================================= */}
        {/* RIGHT COLUMN: INFRASTRUCTURE MAP & ATTACK GRAPH */}
        {/* ========================================================= */}
        <div className="space-y-6">

          {/* Location evidence from the email itself (not IP) */}
          <OriginClues origin={caseData?.origin} />

          {/* Card 1: Relay server location. Only looked-up or recorded facts; never a guess. */}
          <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <MapPin className="w-4 h-4 text-slate-700 dark:text-slate-300" />
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  Relay Server Location
                </h2>
              </div>
              <span className="text-[11px] font-mono font-semibold text-slate-500 dark:text-slate-400">
                {isLoadingGeo ? 'Looking up…' : geoInfo ? `IP lookup · ${geoInfo.source}` : 'Not resolved'}
              </span>
            </div>

            <div className="relative h-56 w-full rounded-xl bg-slate-900 overflow-hidden border border-slate-200 dark:border-slate-800 flex items-center justify-center shadow-inner">
              {geoInfo && typeof geoInfo.lat === 'number' && typeof geoInfo.lon === 'number' ? (
                <>
                  <iframe
                    title="Relay IP location map"
                    className="absolute inset-0 w-full h-full opacity-85 hover:opacity-100 transition filter contrast-125"
                    style={{ border: 0 }}
                    src={`https://www.openstreetmap.org/export/embed.html?bbox=${(geoInfo.lon - 0.08).toFixed(4)}%2C${(geoInfo.lat - 0.05).toFixed(4)}%2C${(geoInfo.lon + 0.08).toFixed(4)}%2C${(geoInfo.lat + 0.05).toFixed(4)}&layer=mapnik&marker=${geoInfo.lat.toFixed(4)}%2C${geoInfo.lon.toFixed(4)}`}
                    loading="lazy"
                  />
                  <div className="absolute bottom-2 left-2 right-2 p-2.5 rounded-lg bg-slate-950/85 backdrop-blur-md border border-slate-800 text-white flex items-center justify-between shadow-lg pointer-events-none">
                    <div className="flex items-center gap-2">
                      <span className="text-xl leading-none">{geoInfo.flag || '🌐'}</span>
                      <div>
                        <div className="text-xs font-bold font-sans flex items-center gap-1.5">
                          <span>{[geoInfo.city, geoInfo.country].filter(Boolean).join(', ') || 'Place not reported'}</span>
                          {geoInfo.countryCode && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-600/80 font-mono font-normal">{geoInfo.countryCode}</span>
                          )}
                        </div>
                        <div className="text-[10px] font-mono text-slate-400">
                          {Math.abs(geoInfo.lat).toFixed(4)}° {geoInfo.lat >= 0 ? 'N' : 'S'}, {Math.abs(geoInfo.lon).toFixed(4)}° {geoInfo.lon >= 0 ? 'E' : 'W'}
                        </div>
                      </div>
                    </div>
                    <div className="text-right font-mono">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-[10px] font-bold">
                        {geoInfo.ip}
                      </span>
                    </div>
                  </div>
                </>
              ) : (
                <div className="relative w-full h-full flex items-center justify-center bg-slate-950/40">
                  <div className="relative z-10 text-center space-y-1 px-4">
                    <div className="text-lg font-bold tracking-tight text-white">
                      {geoInfo
                        ? [geoInfo.city, geoInfo.country].filter(Boolean).join(', ') || 'Place not reported'
                        : caseData?.infrastructure?.location || (isLoadingGeo ? 'Looking up relay IP…' : 'Location not resolved')}
                    </div>
                    <div className="text-[11px] font-mono text-slate-400">
                      {geoInfo?.ip || caseData?.infrastructure?.relayIp || 'No public relay IP in this report'}
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3 pt-1 text-xs font-mono">
              <div>
                <div className="text-[10px] text-slate-400 uppercase font-semibold">NETWORK PROVIDER / ASN</div>
                <div className="text-slate-800 dark:text-slate-200 font-bold mt-0.5 truncate" title={geoInfo?.asn || caseData?.infrastructure?.networkProvider || 'Unknown'}>
                  {geoInfo?.asn || caseData?.infrastructure?.networkProvider || 'Unknown'}
                </div>
              </div>
              <div>
                <div className="text-[10px] text-slate-400 uppercase font-semibold">ISP & CARRIER</div>
                <div className="text-slate-800 dark:text-slate-200 font-bold mt-0.5 truncate" title={geoInfo?.isp || 'Unknown'}>
                  {geoInfo?.isp || 'Unknown'}
                </div>
              </div>
            </div>

            <div className="pt-2 text-[11px] text-slate-400 flex items-start gap-1.5 border-t border-slate-100 dark:border-slate-800">
              <Info className="w-3.5 h-3.5 shrink-0 mt-0.5 text-slate-400" />
              <span>{caseData?.infrastructure?.disclaimer || 'Location of a mail relay server from the Received headers: it locates infrastructure, not the sender.'}</span>
            </div>
          </div>

          {/* Card 2: Correlation Attack Graph */}
          <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-slate-700 dark:text-slate-300" />
                <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                  Correlation Attack Graph
                </h2>
              </div>
              <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200/80 dark:border-blue-800">
                {caseData?.correlationGraph?.clusterId || 'CLUSTER #NETRA'}
              </span>
            </div>

            {/* Node Flow Representation */}
            <div className="py-2 overflow-x-auto">
              <div className="flex items-center justify-between min-w-[480px] gap-2">
                {(caseData?.correlationGraph?.nodes || []).map((node, idx) => {
                  const isLast = idx === (caseData?.correlationGraph?.nodes?.length || 0) - 1;
                  const isDanger = idx >= 3;

                  return (
                    <React.Fragment key={node.id || idx}>
                      <div className="flex flex-col items-center text-center p-2 rounded-xl bg-slate-50 dark:bg-slate-850 border border-slate-200/70 dark:border-slate-800 flex-1 hover:border-blue-400 dark:hover:border-blue-600 transition">
                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center mb-1.5 ${
                          isDanger
                            ? 'bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400'
                            : 'bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400'
                        }`}>
                          {node.type === 'Email' && <Mail className="w-4 h-4" />}
                          {node.type === 'Spoof FQDN' && <Building className="w-4 h-4" />}
                          {node.type === 'Relay IP' && <Server className="w-4 h-4" />}
                          {node.type === 'Auth URL' && <LinkIcon className="w-4 h-4" />}
                          {node.type === 'Payload' && <Bug className="w-4 h-4" />}
                        </div>
                        <div className="text-[11px] font-bold text-slate-800 dark:text-slate-200">
                          {node.type}
                        </div>
                        <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 truncate max-w-[80px]">
                          {node.label}
                        </div>
                      </div>

                      {!isLast && (
                        <div className="text-slate-300 dark:text-slate-600 font-mono text-sm px-1">
                          ➔
                        </div>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            </div>

            {/* Graph Footer */}
            <div className="pt-2 flex items-center justify-between text-[11px] font-mono text-slate-500 dark:text-slate-400 border-t border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-1.5 text-red-600 dark:text-red-400 font-semibold">
                <span className="w-2 h-2 rounded-full bg-red-600 animate-pulse"></span>
                <span>{caseData?.correlationGraph?.statusText || 'Pipeline Verification'}</span>
              </div>
              <span className="text-slate-400">{caseData?.correlationGraph?.mitreCode || 'MITRE ATT&CK'}</span>
            </div>
          </div>

        </div>

      </div>

      {/* JSON Schema Viewer Modal */}
      {showJsonModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-2xl max-h-[80vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-150">
            
            <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <Code className="w-4 h-4 text-blue-600" />
                <h3 className="text-sm font-bold text-slate-900 dark:text-white font-mono">
                  {caseData.caseId} — Forensic Analysis JSON
                </h3>
              </div>
              <button
                onClick={() => setShowJsonModal(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 overflow-y-auto flex-1 font-mono text-xs bg-slate-950 text-slate-200">
              <pre>{JSON.stringify(caseData, null, 2)}</pre>
            </div>

            <div className="p-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-3 bg-slate-50 dark:bg-slate-900/50">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(caseData, null, 2));
                  setCopiedJson(true);
                  setTimeout(() => setCopiedJson(false), 2000);
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                {copiedJson ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedJson ? 'Copied' : 'Copy JSON'}</span>
              </button>

              <button
                onClick={handleExportJson}
                className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-xs font-semibold text-white shadow-sm"
              >
                <FileDown className="w-3.5 h-3.5" />
                <span>Download JSON</span>
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}

export default function ResultPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-xs font-mono text-slate-400">Loading forensic result...</div>}>
      <ResultContent />
    </Suspense>
  );
}
