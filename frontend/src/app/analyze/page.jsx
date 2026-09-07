'use client';

import React, { useState, useEffect, useRef, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  UploadCloud,
  FileText,
  Shield,
  Zap,
  Lock,
  Network,
  Cpu,
  CheckCircle2,
  Clock,
  ArrowRight,
  Sparkles,
  FileCode,
  Layers
} from 'lucide-react';
import { SAMPLE_BEC_EMAIL, SAMPLE_INVOICE_EMAIL, PIPELINE_STAGES } from '@/lib/sampleData';
import { ingestEmailText, ingestEmailFile } from '@/lib/api';
import { parseEmlForensics } from '@/lib/emlParser';

function AnalyzeContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [activeTab, setActiveTab] = useState('upload'); // 'upload' | 'text'
  const [rawEmailText, setRawEmailText] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentStage, setCurrentStage] = useState(0);
  const [activePipelineStages, setActivePipelineStages] = useState(PIPELINE_STAGES);
  const fileInputRef = useRef(null);

  // Check URL query parameters for auto-loading sample
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

  const handleQuickLoad = (type) => {
    setActiveTab('text');
    if (type === 'bec') {
      setRawEmailText(SAMPLE_BEC_EMAIL);
    } else {
      setRawEmailText(SAMPLE_INVOICE_EMAIL);
    }
  };

  const handleFileDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleStartAnalysis = async () => {
    if (activeTab === 'text' && !rawEmailText.trim()) {
      alert('Please enter or paste raw RFC 822 email text.');
      return;
    }
    if (activeTab === 'upload' && !selectedFile) {
      alert('Please select or drop an .eml/.msg file to analyze.');
      return;
    }

    setIsAnalyzing(true);
    setCurrentStage(1);

    let emailContent = '';
    let filename = 'pasted_email.eml';

    if (activeTab === 'text') {
      emailContent = rawEmailText;
    } else if (selectedFile) {
      filename = selectedFile.name;
      try {
        emailContent = await selectedFile.text();
      } catch (err) {
        console.error('Failed reading file:', err);
      }
    }

    let dynamicReport = null;
    if (emailContent) {
      try {
        dynamicReport = await parseEmlForensics(emailContent, filename);
        sessionStorage.setItem('netra_current_report', JSON.stringify(dynamicReport));
      } catch (err) {
        console.error('Error generating dynamic EML report:', err);
      }
    }

    let ingestedEmailId = null;

    // Call ingestion API asynchronously in parallel
    try {
      if (activeTab === 'text') {
        const res = await ingestEmailText(rawEmailText);
        if (res && res.email_id) {
          ingestedEmailId = res.email_id;
          if (dynamicReport) {
            dynamicReport.backendEmailId = res.email_id;
          }
        }
      } else if (selectedFile) {
        const res = await ingestEmailFile(selectedFile);
        if (res && res.email_id) {
          ingestedEmailId = res.email_id;
          if (dynamicReport) {
            dynamicReport.backendEmailId = res.email_id;
          }
        }
      }
      if (dynamicReport) {
        sessionStorage.setItem('netra_current_report', JSON.stringify(dynamicReport));
      }
    } catch (e) {
      console.error(e);
    }

    // Step through the 7 stages with realistic pipeline animation
    const stageTimeouts = [100, 300, 200, 300, 400, 300, 200];
    let step = 1;

    const runStage = () => {
      if (step <= 7) {
        setCurrentStage(step);
        step++;
        setTimeout(runStage, stageTimeouts[step - 2] || 250);
      } else {
        setTimeout(() => {
          setIsAnalyzing(false);
          let targetUrl = '/result';
          if (ingestedEmailId) {
            targetUrl = `/result?id=${ingestedEmailId}`;
          } else if (dynamicReport?.caseId) {
            targetUrl = `/result?caseId=${dynamicReport.caseId}`;
          }
          router.push(targetUrl);
        }, 300);
      }
    };

    runStage();
  };

  return (
    <div className="space-y-6">
      
      {/* Top Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono font-medium text-blue-600 dark:text-blue-400">
            <span className="w-2 h-2 rounded-full bg-blue-600"></span>
            <span>ENGINE CORE V4.0 · ACTIVE NODE</span>
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white mt-1">
            Email Threat Analysis
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-0.5">
            Ingest raw RFC 822 headers or MIME files for real-time forensic dissection.
          </p>
        </div>

        {/* Right Badges */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="px-3 py-1 rounded-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 shadow-xs">
            SHA256 STAMP READY
          </span>
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400 font-semibold shadow-xs">
            <Shield className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
            AIR-GAPPED BUFFER
          </span>
        </div>
      </div>

      {/* Main Grid: Left Ingestion (8 cols) + Right Pipeline (4 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        
        {/* Left Column: Ingestion Console */}
        <div className="lg:col-span-8 space-y-4">
          <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-5 space-y-5">
            
            {/* Header Tabs: MIME / File Upload vs Paste Headers */}
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
                <span>{isAnalyzing ? 'PARSER ACTIVE' : 'PARSER IDLE'}</span>
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
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300">
                    .EML
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300">
                    .MSG
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300">
                    .MBOX
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300">
                    Max 45MB
                  </span>
                </div>
              </div>
            ) : (
              /* Tab 2: Raw RFC Text Area */
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
              {/* Quick Load Buttons */}
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

              {/* Start Forensic Analysis Button */}
              <button
                onClick={handleStartAnalysis}
                disabled={isAnalyzing}
                className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-md shadow-blue-500/20 disabled:opacity-60 transition"
              >
                <span>{isAnalyzing ? 'Running Forensic Pipeline...' : 'Start Forensic Analysis'}</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>

            {/* Bottom 3 Feature Highlights */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3 border-t border-slate-200 dark:border-slate-800">
              <div className="p-3 rounded-lg bg-slate-50/60 dark:bg-slate-850 border border-slate-200/60 dark:border-slate-800 flex items-center gap-3">
                <div className="w-8 h-8 rounded-md bg-blue-100 dark:bg-blue-950/80 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0">
                  <Lock className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                    INTEGRITY
                  </div>
                  <div className="text-xs font-bold text-slate-800 dark:text-slate-200">
                    Client Hashing
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
                    Live Graph Engine
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50/60 dark:bg-slate-850 border border-slate-200/60 dark:border-slate-800 flex items-center gap-3">
                <div className="w-8 h-8 rounded-md bg-emerald-100 dark:bg-emerald-950/80 text-emerald-600 dark:text-emerald-400 flex items-center justify-center shrink-0">
                  <Cpu className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                    BEHAVIORAL
                  </div>
                  <div className="text-xs font-bold text-slate-800 dark:text-slate-200">
                    SIH26106 Neural
                  </div>
                </div>
              </div>
            </div>

          </div>

          {/* Under-card Verification Badges */}
          <div className="flex flex-wrap items-center justify-between text-xs text-slate-500 dark:text-slate-400 px-2 py-1 gap-2">
            <div className="flex items-center gap-4 flex-wrap">
              <span className="inline-flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-slate-400" />
                Zero data retention
              </span>
              <span className="inline-flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-slate-400" />
                Local client-side hashing
              </span>
              <span className="inline-flex items-center gap-1.5 text-blue-600 dark:text-blue-400">
                <Shield className="w-3.5 h-3.5" />
                SIH26106 Verified
              </span>
            </div>

            <div className="inline-flex items-center gap-1.5 font-mono text-[11px] text-emerald-600 dark:text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
              Cryptographic Nonce Generator Active
            </div>
          </div>
        </div>

        {/* Right Column: Analysis Pipeline */}
        <div className="lg:col-span-4">
          <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-5 space-y-5">
            
            {/* Title Header */}
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  Analysis Pipeline
                </h3>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">
                  Deterministic 7-stage evaluation stack
                </div>
              </div>
              <div className="w-7 h-7 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                <Layers className="w-4 h-4" />
              </div>
            </div>

            {/* Stages List */}
            <div className="space-y-3">
              {activePipelineStages.map((stage) => {
                const isCurrent = isAnalyzing && currentStage === stage.id;
                const isPassed = !isAnalyzing || currentStage >= stage.id;

                return (
                  <div
                    key={stage.id}
                    className="flex items-center justify-between text-xs py-1 transition"
                  >
                    <div className="flex items-center gap-2.5">
                      <div className={`w-4 h-4 rounded-full flex items-center justify-center ${
                        isPassed
                          ? 'text-emerald-600 dark:text-emerald-400'
                          : 'text-slate-300 dark:text-slate-600'
                      }`}>
                        <CheckCircle2 className="w-4 h-4" />
                      </div>
                      <span className={`font-medium ${
                        isCurrent
                          ? 'text-blue-600 dark:text-blue-400 font-bold'
                          : 'text-slate-800 dark:text-slate-200'
                      }`}>
                        {stage.name}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                      <span>{stage.latency}</span>
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Cumulative Latency Box */}
            <div className="p-4 rounded-xl bg-blue-50/50 dark:bg-blue-950/30 border border-blue-100 dark:border-blue-900/50 flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-semibold text-blue-800 dark:text-blue-300">
                <Clock className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                <span>Cumulative Latency</span>
              </div>
              <div className="text-xl font-extrabold font-mono text-blue-600 dark:text-blue-400">
                802 ms
              </div>
            </div>

            {/* Telemetry Status Footer */}
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 dark:text-slate-400 pt-1 border-t border-slate-100 dark:border-slate-800">
              <div className="inline-flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                <span>Memory Cache: Clean</span>
              </div>
              <div>TLS 1.3 End-to-End</div>
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
