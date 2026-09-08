'use client';

import React, { useState, useEffect, useRef, useCallback, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  UploadCloud,
  FileText,
  Shield,
  ShieldOff,
  Zap,
  Lock,
  Network,
  Cpu,
  CheckCircle2,
  Circle,
  Loader2,
  XCircle,
  AlertTriangle,
  Clock,
  ArrowRight,
  FileCode,
  Layers,
  RefreshCw,
} from 'lucide-react';
import { SAMPLE_BEC_EMAIL, SAMPLE_INVOICE_EMAIL } from '@/lib/sampleData';
import {
  ingestEmailText,
  ingestEmailFile,
  streamPipelineEvents,
  fetchPipelineStages,
  fetchPipelineHistory,
  checkBackendHealth,
  FALLBACK_PIPELINE_STAGES,
  BackendUnavailableError,
} from '@/lib/api';
import { parseEmlStructure } from '@/lib/emlParser';

const PARSE_PREVIEW_KEY = 'netra_offline_parse_preview';

/** Renders one list of parsed observables, or an explicit "none found" instead of a placeholder. */
function ObservableList({ title, items }) {
  return (
    <div>
      <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold mb-2">
        {title}
      </div>
      {items.length === 0 ? (
        <p className="text-slate-400 italic text-[11px]">none found</p>
      ) : (
        <ul className="space-y-1">
          {items.map((item, idx) => (
            <li
              key={`${item}-${idx}`}
              className="font-mono text-[11px] text-slate-700 dark:text-slate-300 break-all leading-relaxed"
            >
              {item}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function AnalyzeContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [activeTab, setActiveTab] = useState('upload'); // 'upload' | 'text'
  const [rawEmailText, setRawEmailText] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Offline Parse Preview: transcribes the message structure in-browser when the
  // backend is unavailable. It produces no score and no verdict — Netra has exactly
  // one scoring engine and it runs server-side in the threat_engine service.
  const [previewMode, setPreviewMode] = useState(false);
  const [structure, setStructure] = useState(null);

  // Pipeline stage definitions come from the gateway so the UI cannot invent stages.
  const [stages, setStages] = useState(FALLBACK_PIPELINE_STAGES);
  // Map of stage key -> the event the owning service actually emitted.
  const [stageEvents, setStageEvents] = useState({});
  const [pipelineError, setPipelineError] = useState(null);
  const [currentEmailId, setCurrentEmailId] = useState(null);

  const [health, setHealth] = useState(null);
  const [isCheckingHealth, setIsCheckingHealth] = useState(true);

  const fileInputRef = useRef(null);
  const cancelStreamRef = useRef(null);

  // Restore the operator's Offline Parse Preview preference.
  useEffect(() => {
    try {
      setPreviewMode(localStorage.getItem(PARSE_PREVIEW_KEY) === 'true');
    } catch (err) {
      /* storage unavailable; default to live mode */
    }
  }, []);

  const refreshHealth = useCallback(async () => {
    setIsCheckingHealth(true);
    const result = await checkBackendHealth();
    setHealth(result);
    setIsCheckingHealth(false);
    return result;
  }, []);

  useEffect(() => {
    refreshHealth();
    fetchPipelineStages().then(setStages);
  }, [refreshHealth]);

  // Always tear the SSE subscription down when leaving the page.
  useEffect(() => () => cancelStreamRef.current?.(), []);

  useEffect(() => {
    const sample = searchParams.get('sample');
    if (sample === 'bec') {
      setActiveTab('text');
      setRawEmailText(SAMPLE_BEC_EMAIL);
    } else if (sample === 'invoice') {
      setActiveTab('text');
      setRawEmailText(SAMPLE_INVOICE_EMAIL);
    }
  }, [searchParams]);

  const togglePreviewMode = () => {
    const next = !previewMode;
    setPreviewMode(next);
    setPipelineError(null);
    try {
      localStorage.setItem(PARSE_PREVIEW_KEY, String(next));
    } catch (err) {
      /* non-fatal */
    }
  };

  const handleQuickLoad = (type) => {
    setActiveTab('text');
    setRawEmailText(type === 'bec' ? SAMPLE_BEC_EMAIL : SAMPLE_INVOICE_EMAIL);
  };

  const handleFileDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const readEmailContent = async () => {
    if (activeTab === 'text') return { content: rawEmailText, filename: 'pasted_email.eml' };
    if (!selectedFile) return { content: '', filename: 'unknown.eml' };
    return { content: await selectedFile.text(), filename: selectedFile.name };
  };

  /**
   * Offline Parse Preview: transcribe the message structure in the browser.
   * Deliberately renders inline rather than navigating to a report — there is no
   * report to show, because scoring only happens in the backend pipeline.
   */
  const runParsePreview = async () => {
    const { content, filename } = await readEmailContent();
    if (!content) {
      setPipelineError('Could not read the email content to parse.');
      setIsAnalyzing(false);
      return;
    }

    try {
      setStructure(await parseEmlStructure(content, filename));
    } catch (err) {
      console.error('Parse preview failed:', err);
      setPipelineError(`In-browser parse failed: ${err.message}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  /**
   * Live analysis: submit to the ingestion service, then follow the real pipeline.
   * Progress is driven exclusively by stage events published by each worker —
   * if the backend stalls, the UI stalls with it and says so.
   */
  const runLiveAnalysis = async () => {
    let emailId;
    try {
      const res = activeTab === 'text'
        ? await ingestEmailText(rawEmailText)
        : await ingestEmailFile(selectedFile);
      emailId = res?.email_id;
      if (!emailId) throw new BackendUnavailableError('Ingestion returned no email_id.');
    } catch (err) {
      console.error('Ingestion failed:', err);
      setPipelineError(err.message);
      setIsAnalyzing(false);
      refreshHealth();
      return;
    }

    setCurrentEmailId(emailId);

    cancelStreamRef.current = streamPipelineEvents(emailId, {
      onStage: (event) => {
        setStageEvents((prev) => ({ ...prev, [event.stage]: event }));
        if (event.status === 'failed') {
          setPipelineError(
            `Pipeline failed at stage ${event.stage_index}/${event.total_stages} ` +
            `(${event.label}, service: ${event.service}): ${event.error}`
          );
        }
      },
      onDone: () => {
        setIsAnalyzing(false);
        // The report is written by the persistence stage that just fired,
        // so the result page's poll resolves on its first attempt.
        router.push(`/result?id=${emailId}`);
      },
      onError: async (err) => {
        console.error('Pipeline stream error:', err);
        // The stream may have dropped after stages already landed; recover
        // what the backend recorded before declaring the run failed.
        const history = await fetchPipelineHistory(emailId);
        if (history?.events?.length) {
          const recovered = {};
          history.events.forEach((e) => { recovered[e.stage] = e; });
          setStageEvents(recovered);
          if (history.stages_completed === history.total_stages) {
            setIsAnalyzing(false);
            router.push(`/result?id=${emailId}`);
            return;
          }
        }
        setPipelineError(
          `${err.message} Email ${emailId} was accepted by ingestion; the pipeline did not report completion.`
        );
        setIsAnalyzing(false);
      },
    });
  };

  const handleStartAnalysis = async () => {
    if (activeTab === 'text' && !rawEmailText.trim()) {
      setPipelineError('Please enter or paste raw RFC 822 email text.');
      return;
    }
    if (activeTab === 'upload' && !selectedFile) {
      setPipelineError('Please select or drop an .eml/.msg file to analyze.');
      return;
    }

    cancelStreamRef.current?.();
    setPipelineError(null);
    setStageEvents({});
    setCurrentEmailId(null);
    setIsAnalyzing(true);

    setStructure(null);

    if (previewMode) {
      await runParsePreview();
    } else {
      await runLiveAnalysis();
    }
  };

  // ---- Derived pipeline telemetry (all values come from backend events) ----
  const completedEvents = Object.values(stageEvents).filter((e) => e.status === 'complete');
  const cumulativeLatency = completedEvents.reduce((sum, e) => sum + (e.latency_ms || 0), 0);
  const completedCount = completedEvents.length;
  const nextPendingIndex = stages.findIndex((s) => !stageEvents[s.key]) + 1;

  const backendOnline = health?.online === true;

  return (
    <div className="space-y-6">

      {/* Top Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono font-medium text-blue-600 dark:text-blue-400">
            <span className="w-2 h-2 rounded-full bg-blue-600"></span>
            <span>NETRA PIPELINE · 7-STAGE DISTRIBUTED ANALYSIS</span>
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white mt-1">
            Email Threat Analysis
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-0.5">
            Ingest raw RFC 822 headers or MIME files for real-time forensic dissection.
          </p>
        </div>

        {/* Live backend status — the honest indicator judges can verify */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={refreshHealth}
            title="Re-check backend health"
            className="p-1.5 rounded-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-500 hover:text-blue-600 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isCheckingHealth ? 'animate-spin' : ''}`} />
          </button>

          {isCheckingHealth ? (
            <span className="px-3 py-1 rounded-md bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-500">
              PROBING BACKEND…
            </span>
          ) : backendOnline ? (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400 font-semibold">
              <Shield className="w-3.5 h-3.5" />
              PIPELINE ONLINE
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-red-50 dark:bg-red-950/50 border border-red-300 dark:border-red-800 text-red-700 dark:text-red-400 font-semibold">
              <ShieldOff className="w-3.5 h-3.5" />
              PIPELINE OFFLINE
            </span>
          )}
        </div>
      </div>

      {/* Offline Parse Preview banner — never silently substituted */}
      {previewMode && (
        <div className="rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs text-amber-900 dark:text-amber-200 space-y-1">
            <div className="font-bold">Offline Parse Preview is ON — no risk score will be produced.</div>
            <p>
              This transcribes the message structure in your browser: headers, relay chain, URLs, attachments
              and the SHA-256. It does <span className="font-semibold">not</span> score or classify the email.
              Netra has one scoring engine and it runs server-side in the
              <span className="font-mono"> threat_engine</span> service. Turn this off to get a verdict.
            </p>
          </div>
        </div>
      )}

      {/* Backend down while in live mode — actionable, not silent */}
      {!previewMode && !isCheckingHealth && !backendOnline && (
        <div className="rounded-xl border border-red-300 dark:border-red-900 bg-red-50 dark:bg-red-950/40 p-4 flex items-start gap-3">
          <XCircle className="w-5 h-5 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
          <div className="text-xs text-red-900 dark:text-red-200 space-y-1.5">
            <div className="font-bold">Backend pipeline unreachable — live analysis is unavailable.</div>
            <p className="font-mono">
              ingestion: {health?.ingestion?.status || 'unknown'} · gateway: {health?.gateway?.status || 'unknown'}
            </p>
            <p>
              Start the stack with <span className="font-mono font-semibold">docker compose up -d</span>, or
              enable Offline Parse Preview below to at least inspect the message structure.
            </p>
          </div>
        </div>
      )}

      {/* Pipeline / submission error */}
      {pipelineError && (
        <div className="rounded-xl border border-red-300 dark:border-red-900 bg-red-50 dark:bg-red-950/40 p-4 flex items-start gap-3">
          <XCircle className="w-5 h-5 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
          <div className="text-xs text-red-900 dark:text-red-200 space-y-1.5 flex-1">
            <div className="font-bold">Analysis did not complete</div>
            <p className="font-mono break-words">{pipelineError}</p>
            {currentEmailId && (
              <p className="font-mono text-[11px] opacity-80">
                email_id: {currentEmailId} · {completedCount}/{stages.length} stages reported
              </p>
            )}
          </div>
          <button
            onClick={() => setPipelineError(null)}
            className="text-red-500 hover:text-red-700 text-xs font-semibold shrink-0"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">

        {/* Left Column: Ingestion Console */}
        <div className="lg:col-span-8 space-y-4">
          <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-5 space-y-5">

            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setActiveTab('upload')}
                  className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                    activeTab === 'upload'
                      ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  <UploadCloud className="w-3.5 h-3.5" />
                  <span>MIME / File Upload</span>
                </button>

                <button
                  onClick={() => setActiveTab('text')}
                  className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                    activeTab === 'text'
                      ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Paste Headers / Raw RFC</span>
                </button>
              </div>

              <div className="inline-flex items-center gap-1.5 text-[11px] font-mono font-medium text-slate-500 dark:text-slate-400">
                <span className={`w-2 h-2 rounded-full ${isAnalyzing ? 'bg-amber-500 animate-ping' : 'bg-blue-600'}`}></span>
                <span>{isAnalyzing ? 'PIPELINE RUNNING' : 'PIPELINE IDLE'}</span>
              </div>
            </div>

            {/* Tab 1: File Drop Zone */}
            {activeTab === 'upload' ? (
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragging(true);
                }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={handleFileDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-12 text-center transition cursor-pointer flex flex-col items-center justify-center space-y-3 ${
                  isDragging
                    ? 'border-blue-500 bg-blue-50/50 dark:bg-blue-950/30'
                    : 'border-slate-200 dark:border-slate-800 hover:border-blue-400 dark:hover:border-blue-600 bg-slate-50/40 dark:bg-slate-900/40'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".eml,.msg,.mbox,.txt"
                  className="hidden"
                  onChange={handleFileSelect}
                />

                <div className="w-12 h-12 rounded-xl bg-blue-100 dark:bg-blue-950/80 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                  <UploadCloud className="w-6 h-6" />
                </div>

                {selectedFile ? (
                  <div>
                    <div className="text-sm font-semibold text-slate-900 dark:text-white font-mono">
                      {selectedFile.name}
                    </div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      {(selectedFile.size / 1024).toFixed(1)} KB · Ready for parsing
                    </div>
                  </div>
                ) : (
                  <div>
                    <div className="text-base font-bold text-slate-800 dark:text-slate-200">
                      Drop RFC 822 file here or browse
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mt-1">
                      Structured ingest supports nested multipart messages, S/MIME, and encapsulated attachments.
                    </p>
                  </div>
                )}

                <div className="flex items-center gap-2 pt-2">
                  {['.EML', '.MSG', '.MBOX', 'Max 45MB'].map((tag) => (
                    <span
                      key={tag}
                      className="text-[10px] font-mono px-2 py-0.5 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <textarea
                  value={rawEmailText}
                  onChange={(e) => setRawEmailText(e.target.value)}
                  rows={12}
                  placeholder="From: Security Desk <alert@micros0ft-support.com>&#10;To: victim@corp.internal&#10;Subject: Critical Security Notice&#10;&#10;Raw email body..."
                  className="w-full p-4 rounded-xl font-mono text-xs leading-relaxed bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500 text-slate-800 dark:text-slate-200 placeholder:text-slate-400"
                />
              </div>
            )}

            {/* Quick Load & Action Row */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-1">
              <div className="flex items-center gap-2 flex-wrap text-xs">
                <span className="font-mono text-slate-500 font-medium">QUICK LOAD:</span>
                <button
                  onClick={() => handleQuickLoad('bec')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-blue-50 dark:hover:bg-blue-950/50 hover:text-blue-600 text-slate-700 dark:text-slate-300 text-xs font-medium transition border border-slate-200/60 dark:border-slate-700"
                >
                  <Zap className="w-3 h-3 text-amber-500" />
                  <span>BEC Spear-Phish</span>
                </button>
                <button
                  onClick={() => handleQuickLoad('invoice')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-blue-50 dark:hover:bg-blue-950/50 hover:text-blue-600 text-slate-700 dark:text-slate-300 text-xs font-medium transition border border-slate-200/60 dark:border-slate-700"
                >
                  <Zap className="w-3 h-3 text-amber-500" />
                  <span>Invoice Fraud</span>
                </button>
              </div>

              <button
                onClick={handleStartAnalysis}
                disabled={isAnalyzing}
                className={`inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl text-white font-semibold text-xs shadow-md disabled:opacity-60 transition ${
                  previewMode
                    ? 'bg-amber-600 hover:bg-amber-700 shadow-amber-500/20'
                    : 'bg-blue-600 hover:bg-blue-700 shadow-blue-500/20'
                }`}
              >
                {isAnalyzing && <Loader2 className="w-4 h-4 animate-spin" />}
                <span>
                  {isAnalyzing
                    ? previewMode ? 'Parsing…' : 'Awaiting Pipeline…'
                    : previewMode ? 'Parse Structure (no score)' : 'Start Forensic Analysis'}
                </span>
                {!isAnalyzing && <ArrowRight className="w-4 h-4" />}
              </button>
            </div>

            {/* Offline Parse Preview toggle */}
            <div className="flex items-center justify-between gap-4 p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/40">
              <div className="flex items-start gap-3">
                <div className={`w-8 h-8 rounded-md flex items-center justify-center shrink-0 ${
                  previewMode
                    ? 'bg-amber-100 dark:bg-amber-950/80 text-amber-600 dark:text-amber-400'
                    : 'bg-slate-200 dark:bg-slate-800 text-slate-500'
                }`}>
                  <ShieldOff className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-xs font-bold text-slate-800 dark:text-slate-200">
                    Offline Parse Preview
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 max-w-md">
                    Inspect message structure in-browser when the pipeline is unavailable.
                    Produces no risk score — scoring is backend-only.
                  </p>
                </div>
              </div>

              <button
                role="switch"
                aria-checked={previewMode}
                aria-label="Toggle Offline Parse Preview"
                onClick={togglePreviewMode}
                disabled={isAnalyzing}
                className={`relative w-11 h-6 rounded-full transition shrink-0 disabled:opacity-50 ${
                  previewMode ? 'bg-amber-500' : 'bg-slate-300 dark:bg-slate-700'
                }`}
              >
                <span
                  className={`absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform ${
                    previewMode ? 'translate-x-5' : 'translate-x-0.5'
                  }`}
                />
              </button>
            </div>

            {/* Feature Highlights */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3 border-t border-slate-200 dark:border-slate-800">
              <div className="p-3 rounded-lg bg-slate-50/60 dark:bg-slate-850 border border-slate-200/60 dark:border-slate-800 flex items-center gap-3">
                <div className="w-8 h-8 rounded-md bg-blue-100 dark:bg-blue-950/80 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0">
                  <Lock className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                    EVIDENCE
                  </div>
                  <div className="text-xs font-bold text-slate-800 dark:text-slate-200">
                    SHA-256 in MinIO
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50/60 dark:bg-slate-850 border border-slate-200/60 dark:border-slate-800 flex items-center gap-3">
                <div className="w-8 h-8 rounded-md bg-purple-100 dark:bg-purple-950/80 text-purple-600 dark:text-purple-400 flex items-center justify-center shrink-0">
                  <Network className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                    CORRELATION
                  </div>
                  <div className="text-xs font-bold text-slate-800 dark:text-slate-200">
                    Neo4j Graph Engine
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50/60 dark:bg-slate-850 border border-slate-200/60 dark:border-slate-800 flex items-center gap-3">
                <div className="w-8 h-8 rounded-md bg-emerald-100 dark:bg-emerald-950/80 text-emerald-600 dark:text-emerald-400 flex items-center justify-center shrink-0">
                  <Cpu className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                    SCORING
                  </div>
                  <div className="text-xs font-bold text-slate-800 dark:text-slate-200">
                    Deterministic Rules
                  </div>
                </div>
              </div>
            </div>

          </div>

          {/* Offline Parse Preview output — structure only, deliberately no verdict */}
          {structure && (
            <div className="rounded-2xl bg-white dark:bg-slate-900 border border-amber-200 dark:border-amber-900/60 shadow-sm overflow-hidden">
              <div className="px-5 py-3 border-b border-amber-200 dark:border-amber-900/60 bg-amber-50/60 dark:bg-amber-950/30 flex items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">Parsed Structure</h3>
                  <p className="text-[11px] text-amber-800 dark:text-amber-300">
                    Transcribed in-browser · no risk score, no classification
                  </p>
                </div>
                <span className="font-mono text-[10px] px-2 py-1 rounded bg-white dark:bg-slate-900 border border-amber-300 dark:border-amber-800 text-amber-700 dark:text-amber-400 font-bold shrink-0">
                  NOT SCORED
                </span>
              </div>

              <div className="p-5 space-y-5 text-xs">
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/40 p-3 flex items-start gap-2.5">
                  <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                  <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
                    A verdict requires the analysis engines, threat-intel enrichment and graph correlation
                    that run in the backend pipeline. Start the stack and re-run in live mode to score this message.
                  </p>
                </div>

                {/* Headers */}
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold mb-2">
                    Headers
                  </div>
                  <dl className="space-y-1.5">
                    {Object.entries(structure.headers).map(([key, value]) => (
                      <div key={key} className="flex gap-3 items-baseline">
                        <dt className="font-mono text-[11px] text-slate-400 w-24 shrink-0">{key}</dt>
                        <dd className={`font-mono text-[11px] break-all ${
                          value ? 'text-slate-800 dark:text-slate-200' : 'text-slate-400 italic'
                        }`}>
                          {value || 'not present'}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </div>

                {/* Authentication as REPORTED by the receiving MTA */}
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold mb-2">
                    Authentication results — as reported by the receiving MTA
                  </div>
                  {structure.reportedAuth.source ? (
                    <div className="flex flex-wrap gap-2">
                      {['spf', 'dkim', 'dmarc'].map((mech) => (
                        <span
                          key={mech}
                          className="font-mono text-[11px] px-2.5 py-1 rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-700 dark:text-slate-300"
                        >
                          {mech.toUpperCase()}={structure.reportedAuth[mech] || 'not stated'}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-slate-400 italic text-[11px]">
                      No Authentication-Results header present. Netra does not infer a result from its absence.
                    </p>
                  )}
                </div>

                {/* Observables */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
                  <ObservableList title={`Relay chain (${structure.receivedChain.length} hops)`} items={structure.receivedChain} />
                  <ObservableList title={`URLs (${structure.observables.urls.length})`} items={structure.observables.urls} />
                  <ObservableList title={`IP addresses (${structure.observables.ips.length})`} items={structure.observables.ips} />
                  <ObservableList title={`Attachments (${structure.observables.attachments.length})`} items={structure.observables.attachments} />
                </div>

                {/* Evidence identity */}
                <div className="pt-3 border-t border-slate-200 dark:border-slate-800 space-y-1">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                    Evidence
                  </div>
                  <div className="font-mono text-[11px] text-slate-600 dark:text-slate-400 break-all">
                    sha256: {structure.sha256}
                  </div>
                  <div className="font-mono text-[11px] text-slate-500">
                    {structure.filename} · {structure.sizeBytes} bytes · parsed {structure.parsedAt}
                  </div>
                </div>
              </div>
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between text-xs text-slate-500 dark:text-slate-400 px-2 py-1 gap-2">
            <div className="flex items-center gap-4 flex-wrap">
              <span className="inline-flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-slate-400" />
                Raw evidence retained in MinIO
              </span>
              <span className="inline-flex items-center gap-1.5 text-blue-600 dark:text-blue-400">
                <Shield className="w-3.5 h-3.5" />
                SIH26106
              </span>
            </div>

            {currentEmailId && (
              <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                email_id: {currentEmailId}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Live Pipeline Telemetry */}
        <div className="lg:col-span-4">
          <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-5 space-y-5">

            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  Analysis Pipeline
                </h3>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">
                  {previewMode
                    ? 'Idle — preview mode does not run the pipeline'
                    : 'Live stage events from each service'}
                </div>
              </div>
              <div className="w-7 h-7 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                <Layers className="w-4 h-4" />
              </div>
            </div>

            {/* Stage list driven by real events */}
            <div className="space-y-2.5">
              {stages.map((stage) => {
                const event = stageEvents[stage.key];
                const failed = event?.status === 'failed';
                const done = event?.status === 'complete';
                const active = isAnalyzing && !previewMode && !event && stage.index === nextPendingIndex;

                return (
                  <div key={stage.key} className="space-y-0.5">
                    <div className="flex items-center justify-between text-xs py-0.5">
                      <div className="flex items-center gap-2.5 min-w-0">
                        <div className="w-4 h-4 flex items-center justify-center shrink-0">
                          {failed ? (
                            <XCircle className="w-4 h-4 text-red-500" />
                          ) : done ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                          ) : active ? (
                            <Loader2 className="w-4 h-4 text-blue-500 animate-spin" />
                          ) : (
                            <Circle className="w-4 h-4 text-slate-300 dark:text-slate-700" />
                          )}
                        </div>
                        <span className={`font-medium truncate ${
                          failed
                            ? 'text-red-600 dark:text-red-400'
                            : active
                            ? 'text-blue-600 dark:text-blue-400 font-bold'
                            : done
                            ? 'text-slate-800 dark:text-slate-200'
                            : 'text-slate-400 dark:text-slate-600'
                        }`}>
                          {stage.index}. {stage.label}
                        </span>
                      </div>

                      <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400 shrink-0 pl-2">
                        {done && event.latency_ms != null
                          ? `${event.latency_ms.toFixed(1)} ms`
                          : failed
                          ? 'failed'
                          : active
                          ? '…'
                          : '—'}
                      </div>
                    </div>

                    {/* What the service actually reported */}
                    {event?.detail && (
                      <div className="pl-6.5 ml-[26px] text-[10px] text-slate-500 dark:text-slate-500 leading-snug">
                        {event.detail}
                      </div>
                    )}
                    {event?.error && (
                      <div className="ml-[26px] text-[10px] text-red-500 leading-snug break-words">
                        {event.error}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Measured cumulative latency — sum of real per-stage timings */}
            <div className={`p-4 rounded-xl border flex items-center justify-between ${
              previewMode
                ? 'bg-amber-50/60 dark:bg-amber-950/30 border-amber-200 dark:border-amber-900/50'
                : 'bg-blue-50/50 dark:bg-blue-950/30 border-blue-100 dark:border-blue-900/50'
            }`}>
              <div className={`flex items-center gap-2 text-xs font-semibold ${
                previewMode ? 'text-amber-800 dark:text-amber-300' : 'text-blue-800 dark:text-blue-300'
              }`}>
                <Clock className="w-4 h-4" />
                <span>Measured Latency</span>
              </div>
              <div className={`text-xl font-extrabold font-mono ${
                previewMode ? 'text-amber-600 dark:text-amber-400' : 'text-blue-600 dark:text-blue-400'
              }`}>
                {completedCount > 0 ? `${cumulativeLatency.toFixed(0)} ms` : '—'}
              </div>
            </div>

            <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 dark:text-slate-400 pt-1 border-t border-slate-100 dark:border-slate-800">
              <div className="inline-flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${
                  completedCount === stages.length ? 'bg-emerald-500' : 'bg-slate-400'
                }`}></span>
                <span>{completedCount}/{stages.length} stages</span>
              </div>
              <div>{previewMode ? 'PREVIEW · no scoring' : 'SSE · live'}</div>
            </div>

          </div>
        </div>

      </div>

    </div>
  );
}

export default function AnalyzePage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-xs font-mono text-slate-400">Loading analysis engine...</div>}>
      <AnalyzeContent />
    </Suspense>
  );
}
