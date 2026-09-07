'use client';

import React, { useState, useEffect, useMemo, Suspense } from 'react';
import Link from 'next/link';
import {
  Shield,
  ShieldAlert,
  FileDown,
  Code,
  Copy,
  Check,
  Search,
  Calendar,
  Filter,
  ArrowRight,
  Lock,
  Clock,
  Zap,
  AlertTriangle,
  AlertCircle,
  ShieldCheck,
  ChevronDown,
  X
} from 'lucide-react';
import { SAMPLE_CASE_0891, INVESTIGATION_ARCHIVE, CASES_MAP } from '@/lib/sampleData';
import { fetchReportsList, fetchReportDetails } from '@/lib/api';
import { transformBackendReport } from '@/lib/emlParser';

export default function ReportPage() {
  const [currentCase, setCurrentCase] = useState(SAMPLE_CASE_0891);
  const [archiveList, setArchiveList] = useState(INVESTIGATION_ARCHIVE);
  const [copiedSha, setCopiedSha] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [showJsonModal, setShowJsonModal] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);

  useEffect(() => {
    // 1. Fetch live persistent reports from API Gateway
    fetchReportsList().then((backendReports) => {
      if (Array.isArray(backendReports) && backendReports.length > 0) {
        const liveItems = backendReports.map((r) => {
          const score = r.risk_score !== undefined ? r.risk_score : 0;
          const isMal = r.classification === 'MALICIOUS' || score >= 61;
          const isSusp = r.classification === 'SUSPICIOUS' || score >= 21;
          return {
            caseId: `#${(r.email_id || '').substring(0, 8)}`,
            emailId: r.email_id,
            date: r.created_at ? new Date(r.created_at).toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Recently',
            targetMailbox: r.sender || 'Unknown Sender',
            detectedThreat: r.subject || (isMal ? 'Malicious Threat' : isSusp ? 'Suspicious Relay' : 'Clean Communication'),
            riskScore: `${score} / 100`,
            scoreNum: score,
            status: isMal ? 'Quarantined' : isSusp ? 'Flagged' : 'Delivered',
            statusColor: isMal ? 'red' : isSusp ? 'orange' : 'green',
            hasDot: isMal,
          };
        });
        setArchiveList(liveItems);

        // Auto-load details for the most recent email if none selected yet
        if (backendReports[0]?.email_id) {
          fetchReportDetails(backendReports[0].email_id).then((full) => {
            if (full) {
              const transformed = transformBackendReport(full);
              if (transformed) setCurrentCase(transformed);
            }
          });
        }
      }
    });

    // 2. Check query param for specific ID
    if (typeof window !== 'undefined') {
      const urlParams = new URLSearchParams(window.location.search);
      const emailId = urlParams.get('id') || urlParams.get('email_id');
      if (emailId) {
        fetchReportDetails(emailId).then((full) => {
          if (full) {
            const transformed = transformBackendReport(full);
            if (transformed) setCurrentCase(transformed);
          }
        });
        return;
      }
    }

    // 3. Fallback to newly analyzed session storage
    const stored = sessionStorage.getItem('netra_current_report');
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        if (parsed && parsed.caseId) {
          setCurrentCase(parsed);
        }
      } catch (err) {
        console.error('Failed reading stored report in report page:', err);
      }
    }
  }, []);

  const handleCopySha = () => {
    navigator.clipboard.writeText(currentCase.sha256);
    setCopiedSha(true);
    setTimeout(() => setCopiedSha(false), 2000);
  };

  const handleExportPdf = () => {
    window.print();
  };

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(currentCase, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `${currentCase.caseId}-forensic-report.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Filtered case archive table
  const filteredArchive = useMemo(() => {
    return archiveList.filter((item) => {
      const matchesSearch =
        item.caseId.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.targetMailbox.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.detectedThreat.toLowerCase().includes(searchQuery.toLowerCase());

      if (severityFilter === 'MALICIOUS') {
        return matchesSearch && item.scoreNum >= 80;
      }
      if (severityFilter === 'BENIGN') {
        return matchesSearch && item.scoreNum < 50;
      }
      return matchesSearch;
    });
  }, [archiveList, searchQuery, severityFilter]);

  return (
    <div className="space-y-8">
      
      {/* Top Breadcrumbs & Consensus Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono border-b border-slate-200/80 dark:border-slate-800 pb-3">
        <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
          <Link href="/investigations" className="hover:text-blue-600 transition">ARCHIVE</Link>
          <span>/</span>
          <span className="text-slate-400">SIH26106-CASES</span>
          <span>/</span>
          <span className="font-bold text-blue-600 dark:text-blue-400">{currentCase.caseId}</span>
        </div>

        <div className="flex items-center gap-3 text-slate-500 dark:text-slate-400">
          <span className="inline-flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400 font-semibold">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            Consensus Engine: {currentCase.consensusState}
          </span>
          <span className="text-slate-300 dark:text-slate-700">|</span>
          <span>Block #{currentCase.blockNumber}</span>
        </div>
      </div>

      {/* Case Header Dossier Banner */}
      <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-6 space-y-4">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          
          <div className="space-y-2">
            <div className="flex items-center gap-3 flex-wrap text-xs font-mono">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-red-100 dark:bg-red-950/70 text-red-700 dark:text-red-400 font-bold border border-red-200 dark:border-red-900/50">
                <span className="w-1.5 h-1.5 rounded-full bg-red-600"></span>
                {currentCase.statusBadge}
              </span>
              <span className="text-slate-500 dark:text-slate-400">
                🕒 {currentCase.timestampUtc}
              </span>
              <span className="text-slate-400">
                Vault ID: {currentCase.vaultId}
              </span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white">
              {currentCase.caseNumber}
            </h1>

            <div className="flex items-center gap-3 text-xs font-mono text-slate-500 dark:text-slate-400 flex-wrap">
              <div className="flex items-center gap-1.5 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded">
                <span>SHA-256: {currentCase.shaShort}</span>
                <button
                  onClick={handleCopySha}
                  className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-0.5"
                  title="Copy full hash"
                >
                  {copiedSha ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
              <span className="inline-flex items-center gap-1 text-blue-600 dark:text-blue-400">
                <Shield className="w-3.5 h-3.5" />
                Custody proof anchored to {currentCase.custodyNetwork}
              </span>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-3 shrink-0 w-full lg:w-auto justify-end no-print">
            <button
              onClick={() => setShowJsonModal(true)}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700 text-xs font-semibold shadow-xs transition"
            >
              <Code className="w-3.5 h-3.5" />
              <span>Export JSON Schema</span>
            </button>

            <button
              onClick={handleExportPdf}
              className="inline-flex items-center gap-2 px-5 py-2 rounded-xl bg-[#0b1b3d] dark:bg-blue-600 hover:bg-[#142858] dark:hover:bg-blue-500 text-white text-xs font-semibold shadow-md transition"
            >
              <FileDown className="w-3.5 h-3.5" />
              <span>Export PDF Report</span>
            </button>
          </div>

        </div>
      </div>

      {/* 4 KPI Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* KPI 1: Final Verdict */}
        <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-[11px] font-mono uppercase text-slate-400 font-semibold">
            <span>FINAL VERDICT</span>
            <span className="w-2 h-2 rounded-full bg-red-600"></span>
          </div>
          <div className="mt-3">
            <div className="text-2xl font-extrabold text-red-600 dark:text-red-500 tracking-tight font-mono">
              {currentCase.kpis.finalVerdict.status}
            </div>
            <div className="w-16 h-1 bg-red-600 rounded-full mt-2 mb-2"></div>
            <div className="text-xs text-slate-500 dark:text-slate-400 font-mono">
              Confidence: {currentCase.kpis.finalVerdict.confidence} | <span className="text-red-500 font-semibold">{currentCase.kpis.finalVerdict.level}</span>
            </div>
          </div>
        </div>

        {/* KPI 2: Threat Category */}
        <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-[11px] font-mono uppercase text-slate-400 font-semibold">
            <span>THREAT CATEGORY</span>
            <Shield className="w-4 h-4 text-blue-500" />
          </div>
          <div className="mt-3">
            <div className="text-xl font-bold text-slate-900 dark:text-white tracking-tight">
              {currentCase.kpis.threatCategory.category}
            </div>
            <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Subtype: {currentCase.kpis.threatCategory.subtype}
            </div>
            <div className="text-xs font-mono text-slate-500 dark:text-slate-400 mt-2 flex items-center gap-1.5">
              <span>DKIM Misalignment</span>
              <span className="text-red-600 font-bold">{currentCase.kpis.threatCategory.dkimResult}</span>
            </div>
          </div>
        </div>

        {/* KPI 3: Containment Impact */}
        <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-[11px] font-mono uppercase text-slate-400 font-semibold">
            <span>CONTAINMENT IMPACT</span>
            <ShieldCheck className="w-4 h-4 text-blue-500" />
          </div>
          <div className="mt-3">
            <div className="text-xl font-bold text-blue-700 dark:text-blue-400 tracking-tight">
              {currentCase.kpis.containmentImpact.status}
            </div>
            <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono truncate">
              Target: {currentCase.kpis.containmentImpact.targetMailbox}
            </div>
            <div className="text-xs font-mono text-slate-500 dark:text-slate-400 mt-2">
              Recipients Protected: <span className="font-bold text-slate-800 dark:text-slate-200">{currentCase.kpis.containmentImpact.recipientsProtected}</span>
            </div>
          </div>
        </div>

        {/* KPI 4: Pipeline Latency */}
        <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-[11px] font-mono uppercase text-slate-400 font-semibold">
            <span>PIPELINE LATENCY</span>
            <Zap className="w-4 h-4 text-blue-500" />
          </div>
          <div className="mt-3">
            <div className="text-2xl font-extrabold text-slate-900 dark:text-white tracking-tight font-mono">
              {currentCase.kpis.pipelineLatency.totalTime}
            </div>
            <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono">
              Nodes Traversed: {currentCase.kpis.pipelineLatency.nodesTraversed}
            </div>
            <div className="text-xs font-mono text-slate-500 dark:text-slate-400 mt-2 flex items-center gap-1.5">
              <span>Heuristic Pass:</span>
              <span className="text-emerald-600 dark:text-emerald-400 font-semibold">{currentCase.kpis.pipelineLatency.heuristicStatus}</span>
            </div>
          </div>
        </div>

      </div>

      {/* Relay Hop Traversal Analysis Section */}
      <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 border-b border-slate-100 dark:border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-slate-700 dark:text-slate-300" />
            <h2 className="text-base font-bold text-slate-900 dark:text-white">
              Relay Hop Traversal Analysis
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-400">
            MIME Envelope Path · Received Headers Chronology
          </span>
        </div>

        {/* 4 Hops Horizontal Chain */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">
          {currentCase.relayHops.map((hop, idx) => {
            const isSinkhole = hop.highlight === 'quarantine';

            return (
              <div
                key={idx}
                className={`p-4 rounded-xl border flex flex-col justify-between transition ${
                  isSinkhole
                    ? 'bg-blue-50/70 dark:bg-blue-950/40 border-blue-300 dark:border-blue-800'
                    : 'bg-slate-50/50 dark:bg-slate-850 border-slate-200/80 dark:border-slate-800'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className={`text-[10px] font-mono font-bold ${
                      isSinkhole ? 'text-blue-700 dark:text-blue-300' : 'text-slate-500'
                    }`}>
                      {hop.hopNumber}
                    </span>
                    {hop.icon === 'AlertTriangle' && <AlertTriangle className="w-4 h-4 text-red-500" />}
                    {hop.icon === 'AlertCircle' && <AlertCircle className="w-4 h-4 text-red-500" />}
                    {hop.icon === 'ShieldCheck' && <ShieldCheck className="w-4 h-4 text-emerald-500" />}
                    {hop.icon === 'Lock' && <Lock className="w-4 h-4 text-blue-600 dark:text-blue-400" />}
                  </div>

                  <div className="text-sm font-bold font-mono text-slate-900 dark:text-white mt-2">
                    {hop.ip}
                  </div>

                  <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    {hop.description}
                  </div>
                </div>

                <div className="pt-3 mt-3 border-t border-slate-200/60 dark:border-slate-800 text-[11px] font-mono flex items-center justify-between">
                  <span className="text-slate-400">{isSinkhole ? 'STATUS' : 'AUTH'}</span>
                  <span className={`font-bold ${
                    hop.authType === 'fail'
                      ? 'text-red-600 dark:text-red-400'
                      : hop.authType === 'pass'
                      ? 'text-emerald-600 dark:text-emerald-400'
                      : 'text-blue-700 dark:text-blue-300'
                  }`}>
                    {hop.authStatus || hop.statusBadge}
                  </span>
                </div>

                <div className="text-[10px] font-mono text-slate-400 flex items-center justify-between pt-1">
                  <span>LATENCY</span>
                  <span>{hop.latency}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Case Archive / Investigations Table */}
      <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-6 space-y-4">
        
        {/* Search and Filters Bar */}
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          {/* Search Box */}
          <div className="relative w-full md:w-96">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 transform -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search case ID, target mailbox, threat hash..."
              className="w-full pl-10 pr-4 py-2 rounded-xl text-xs bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {/* Filter Dropdowns */}
          <div className="flex items-center gap-3 w-full md:w-auto justify-end text-xs">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-2 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 font-medium focus:outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="MALICIOUS">Malicious (&ge;80)</option>
              <option value="BENIGN">Benign (&lt;50)</option>
            </select>

            <button className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 font-medium hover:bg-slate-100 transition">
              <Calendar className="w-3.5 h-3.5 text-slate-400" />
              <span>Last 30 Days</span>
            </button>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-[11px] font-mono text-slate-400 uppercase border-b border-slate-200/80 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50">
              <tr>
                <th className="py-3 px-4 font-semibold">CASE ID</th>
                <th className="py-3 px-4 font-semibold">DATE</th>
                <th className="py-3 px-4 font-semibold">TARGET MAILBOX</th>
                <th className="py-3 px-4 font-semibold">DETECTED THREAT</th>
                <th className="py-3 px-4 font-semibold">RISK SCORE</th>
                <th className="py-3 px-4 font-semibold">STATUS</th>
                <th className="py-3 px-4 font-semibold text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-mono">
              {filteredArchive.map((row) => (
                <tr
                  key={row.caseId}
                  className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40 transition"
                >
                  <td className="py-3.5 px-4 font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                    <span>{row.caseId}</span>
                    {row.hasDot && <span className="w-1.5 h-1.5 rounded-full bg-red-600"></span>}
                  </td>
                  <td className="py-3.5 px-4 text-slate-500 dark:text-slate-400 font-sans">
                    {row.date}
                  </td>
                  <td className="py-3.5 px-4 text-slate-700 dark:text-slate-300">
                    {row.targetMailbox}
                  </td>
                  <td className="py-3.5 px-4 font-sans font-medium text-slate-800 dark:text-slate-200">
                    {row.detectedThreat}
                  </td>
                  <td className="py-3.5 px-4 font-bold">
                    <span className={
                      row.scoreNum >= 80 ? 'text-red-600 dark:text-red-400' :
                      row.scoreNum >= 50 ? 'text-amber-600 dark:text-amber-400' :
                      'text-emerald-600 dark:text-emerald-400'
                    }>
                      {row.riskScore}
                    </span>
                  </td>
                  <td className="py-3.5 px-4">
                    <span className={`text-[11px] font-sans font-semibold px-2 py-0.5 rounded-full ${
                      row.statusColor === 'red'
                        ? 'bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400 border border-red-200/60'
                        : row.statusColor === 'blue'
                        ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 border border-blue-200/60'
                        : row.statusColor === 'green'
                        ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 border border-emerald-200/60'
                        : 'bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 border border-amber-200/60'
                    }`}>
                      {row.status}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={() => {
                        if (row.emailId) {
                          fetchReportDetails(row.emailId).then((full) => {
                            if (full) {
                              const transformed = transformBackendReport(full);
                              if (transformed) setCurrentCase(transformed);
                            }
                          });
                        } else if (row.fullCase) {
                          setCurrentCase(row.fullCase);
                        } else if (CASES_MAP[row.caseId]) {
                          setCurrentCase(CASES_MAP[row.caseId]);
                        }
                        window.scrollTo({ top: 0, behavior: 'smooth' });
                      }}
                      className="inline-flex items-center gap-1 text-blue-600 dark:text-blue-400 hover:underline font-sans font-semibold text-xs"
                    >
                      <span>View Dossier</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
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
                  {currentCase.caseId} — Forensic JSON Schema
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
              <pre>{JSON.stringify(currentCase, null, 2)}</pre>
            </div>

            <div className="p-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-3 bg-slate-50 dark:bg-slate-900/50">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(currentCase, null, 2));
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
                <span>Download Schema</span>
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
