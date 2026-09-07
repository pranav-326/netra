'use client';

import React from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Mail,
  ShieldCheck,
  Zap,
  RotateCcw,
  FileCode,
  Brain,
  Search,
  Network,
  Gauge,
  Lock,
  ArrowRight,
  ExternalLink,
  Play,
  FlaskConical
} from 'lucide-react';

export default function HomePage() {
  const router = useRouter();

  const loadSampleInvestigation = () => {
    router.push('/analyze?sample=bec');
  };

  const metricCards = [
    {
      label: 'VOLUME PROCESSED',
      value: '48,290+',
      subtext: 'Analyzed & verified',
      icon: Mail,
      iconColor: 'text-blue-500',
    },
    {
      label: 'MODEL PRECISION',
      value: '99.4%',
      subtext: 'Verified ground truth',
      icon: ShieldCheck,
      iconColor: 'text-emerald-500',
    },
    {
      label: 'SPEED',
      value: '<1.8s',
      subtext: 'Hop telemetry latency',
      icon: Zap,
      iconColor: 'text-blue-500',
    },
    {
      label: 'PRIVACY',
      value: 'Zero-Retention',
      subtext: 'Ephemeral RAM compute',
      icon: RotateCcw,
      iconColor: 'text-emerald-500',
    },
  ];

  const pipelineStages = [
    {
      step: '01 // INGEST',
      title: 'MIME Parse',
      desc: 'RFC 822 extraction',
      tag: 'RAW ENVELOPE',
      icon: FileCode,
    },
    {
      step: '02 // NLP & LLM',
      title: 'AI Analysis',
      desc: 'Semantic intent classification',
      tag: 'BEC VECTORS',
      icon: Brain,
    },
    {
      step: '03 // IOC QUERY',
      title: 'Threat Intel',
      desc: 'Multi-source reputation scoring',
      tag: 'FEED SYNC',
      icon: Search,
    },
    {
      step: '04 // NETWORK',
      title: 'Infrastructure',
      desc: 'Relay route verification',
      tag: 'ASN TRACING',
      icon: Network,
    },
    {
      step: '05 // EVAL',
      title: 'Risk Scoring',
      desc: 'Bayesian confidence engine',
      tag: 'METRIC 0-100',
      icon: Gauge,
    },
    {
      step: '06 // PROOF',
      title: 'Forensics',
      desc: 'Immutable chain hash',
      tag: 'CUSTODY SEALED',
      icon: Lock,
    },
  ];

  return (
    <div className="space-y-12 py-4">
      
      {/* Hero Section */}
      <section className="text-center max-w-4xl mx-auto pt-6 pb-2 space-y-5">
        
        {/* Top SIH Badge */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-blue-50 dark:bg-blue-950/50 border border-blue-200/80 dark:border-blue-800/60 text-xs font-mono font-medium text-blue-700 dark:text-blue-300">
          <span className="w-2 h-2 rounded-full bg-blue-600 animate-pulse"></span>
          <span>SIH26106 · Blockchain & Cybersecurity</span>
        </div>

        {/* Hero Title */}
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-slate-900 dark:text-white">
          See Beyond the Email.
        </h1>

        {/* Hero Subtitle */}
        <p className="text-base sm:text-lg text-slate-600 dark:text-slate-400 max-w-2xl mx-auto leading-relaxed">
          AI-powered email threat detection, geolocation, and forensic intelligence.
        </p>

        {/* Hero CTAs */}
        <div className="flex items-center justify-center gap-4 pt-2">
          <Link
            href="/analyze"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm shadow-md shadow-blue-500/20 transition-all hover:translate-y-[-1px]"
          >
            <span>Analyze Email</span>
            <ArrowRight className="w-4 h-4" />
          </Link>

          <a
            href="#deterministic-pipeline"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700/80 font-medium text-sm shadow-sm transition"
          >
            <span>See How It Works</span>
            <ExternalLink className="w-4 h-4 text-slate-400" />
          </a>
        </div>
      </section>

      {/* 4 Metric KPI Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {metricCards.map((item, idx) => {
          const IconComp = item.icon;
          return (
            <div
              key={idx}
              className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm hover:shadow transition-shadow relative overflow-hidden group"
            >
              <div className="flex items-start justify-between">
                <span className="text-[11px] font-mono tracking-wider text-slate-500 dark:text-slate-400 font-semibold">
                  {item.label}
                </span>
                <IconComp className={`w-4 h-4 ${item.iconColor}`} />
              </div>
              <div className="mt-3">
                <div className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white font-mono">
                  {item.value}
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  {item.subtext}
                </div>
              </div>
            </div>
          );
        })}
      </section>

      {/* How It Works: Deterministic Pipeline */}
      <section id="deterministic-pipeline" className="space-y-4 pt-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <div className="text-xs font-mono uppercase tracking-wider text-blue-600 dark:text-blue-400 font-semibold">
              HOW IT WORKS
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white mt-1">
              Deterministic Pipeline
            </h2>
          </div>

          <div className="inline-flex items-center gap-2 text-xs font-mono px-3 py-1 rounded-md bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200/70 dark:border-emerald-800/50 text-emerald-700 dark:text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span>Pipeline State: IDLE READY</span>
          </div>
        </div>

        {/* 6 Pipeline Stage Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3 pt-2">
          {pipelineStages.map((stage, idx) => {
            const Icon = stage.icon;
            return (
              <div
                key={idx}
                className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 flex flex-col justify-between hover:border-blue-300 dark:hover:border-blue-700 transition"
              >
                <div>
                  <div className="text-[10px] font-mono text-slate-400 dark:text-slate-500 font-semibold mb-2">
                    {stage.step}
                  </div>
                  <div className="w-8 h-8 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center mb-3">
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="font-semibold text-sm text-slate-900 dark:text-white">
                    {stage.title}
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-snug">
                    {stage.desc}
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80">
                  <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                    {stage.tag}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Sample Investigation Quick Load Banner */}
      <section className="p-4 sm:p-5 rounded-xl bg-white dark:bg-slate-900 border border-blue-200/80 dark:border-blue-900/60 shadow-sm flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-4 w-full sm:w-auto">
          <div className="w-10 h-10 rounded-xl bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0 border border-blue-200 dark:border-blue-800">
            <FlaskConical className="w-5 h-5" />
          </div>
          <div>
            <div className="font-semibold text-sm text-slate-900 dark:text-white">
              Try sample investigation: RFC 822 MIME
            </div>
            <div className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
              4-hop relay anomaly · Urgent wire transfer spoof · BEC Flag #CR-942
            </div>
          </div>
        </div>

        <button
          onClick={loadSampleInvestigation}
          className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-sm transition shrink-0"
        >
          <Play className="w-3.5 h-3.5 fill-white" />
          <span>Load Sample</span>
        </button>
      </section>

    </div>
  );
}
