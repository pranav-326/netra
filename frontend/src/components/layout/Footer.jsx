'use client';

import React from 'react';
import Link from 'next/link';

export default function Footer() {
  return (
    <footer className="w-full border-t border-slate-200 dark:border-slate-800 bg-[#f4f6f8]/70 dark:bg-[#0c1017]/70 py-6 mt-16 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-4 text-xs text-slate-500 dark:text-slate-400">
        
        {/* Left: Copyright & Operational State */}
        <div className="flex items-center gap-3 flex-wrap justify-center md:justify-start">
          <span>© 2025 200 OK — AI Email Forensics. SIH26106.</span>
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 text-[11px] font-mono border border-emerald-200 dark:border-emerald-800/60">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
            All Systems Operational
          </span>
        </div>

        {/* Right: Technical Links */}
        <div className="flex items-center gap-5 text-slate-500 dark:text-slate-400">
          <Link href="/report" className="hover:text-slate-900 dark:hover:text-slate-200 transition">
            Chain of Custody
          </Link>
          <span className="text-slate-300 dark:text-slate-700">·</span>
          <Link href="#" className="hover:text-slate-900 dark:hover:text-slate-200 transition">
            Privacy Policy
          </Link>
          <span className="text-slate-300 dark:text-slate-700">·</span>
          <Link href="#" className="hover:text-slate-900 dark:hover:text-slate-200 transition">
            Verification Protocol
          </Link>
          <span className="text-slate-300 dark:text-slate-700">·</span>
          <Link href="http://localhost:8080/docs" target="_blank" className="hover:text-slate-900 dark:hover:text-slate-200 transition">
            API Spec
          </Link>
        </div>
      </div>
    </footer>
  );
}
