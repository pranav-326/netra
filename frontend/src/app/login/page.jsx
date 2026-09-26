'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AlertTriangle, Loader2, Lock, ScrollText, UserPlus } from 'lucide-react';
import NetraMark from '@/components/brand/NetraMark';
import { getSession, safeNextPath, signIn } from '@/lib/auth';

const nextPath = () =>
  typeof window === 'undefined' ? '/' : safeNextPath(new URLSearchParams(window.location.search).get('next'));

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Already signed in: go straight on.
  useEffect(() => {
    if (getSession()) router.replace(nextPath());
  }, [router]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      await signIn(username.trim(), password);
      router.replace(nextPath());
    } catch (err) {
      setError(err.message);
      setPassword('');
      setSubmitting(false);
    }
  };

  const field =
    'w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm ' +
    'text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-600 ' +
    'focus:border-brand-600 disabled:opacity-60';

  return (
    <div className="flex justify-center py-10 sm:py-16">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-2.5 mb-6">
          <NetraMark className="w-9 h-9 text-brand-600 dark:text-brand-400" />
          <div>
            <h1 className="text-lg font-bold tracking-tight text-slate-900 dark:text-white">Sign in to Netra</h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">Email threat intelligence &amp; forensics</p>
          </div>
        </div>

        <form
          onSubmit={handleSubmit}
          className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-6 space-y-4"
          noValidate
        >
          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 text-xs text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 rounded-lg p-3"
            >
              <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}

          <div className="space-y-1.5">
            <label htmlFor="username" className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
              Username
            </label>
            <input
              id="username"
              name="username"
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={submitting}
              className={field}
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="password" className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={submitting}
              className={field}
            />
          </div>

          <button
            type="submit"
            disabled={submitting || !username.trim() || !password}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg bg-brand-600 hover:bg-brand-700 text-white shadow-brand transition disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-600 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-slate-950"
          >
            {submitting ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" /> : <Lock className="w-4 h-4" aria-hidden="true" />}
            {submitting ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <button
          type="button"
          onClick={() => router.push('/register')}
          className="w-full mt-3 flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
        >
          <UserPlus className="w-4 h-4" aria-hidden="true" />
          Create an account
        </button>

        <p className="mt-4 flex items-start gap-2 text-[11px] leading-relaxed text-slate-500 dark:text-slate-400">
          <ScrollText className="w-3.5 h-3.5 shrink-0 mt-px" aria-hidden="true" />
          <span>
            Access is recorded. Every sign-in, report view and email submission is written to the audit
            trail with your username. Your account can upload EML files and view its own analyses.
          </span>
        </p>
      </div>
    </div>
  );
}
