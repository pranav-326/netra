'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AlertTriangle, Loader2, Lock, UserPlus } from 'lucide-react';
import NetraMark from '@/components/brand/NetraMark';
import { getSession, signIn } from '@/lib/auth';
import { registerUser } from '@/lib/api';

const field =
  'w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm ' +
  'text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-600 ' +
  'focus:border-brand-600 disabled:opacity-60';

export default function RegisterPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (getSession()) router.replace('/');
  }, [router]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    if (password !== confirmation) {
      setError('Passwords do not match.');
      return;
    }
    setSubmitting(true);
    try {
      await registerUser(username.trim(), password);
      await signIn(username.trim(), password);
      router.replace('/analyze');
    } catch (err) {
      setError(err.message);
      setSubmitting(false);
    }
  };

  return (
    <div className="flex justify-center py-10 sm:py-16">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-2.5 mb-6">
          <NetraMark className="w-9 h-9 text-brand-600 dark:text-brand-400" />
          <div>
            <h1 className="text-lg font-bold tracking-tight text-slate-900 dark:text-white">Create your Netra account</h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">Upload an email and review its threat analysis</p>
          </div>
        </div>

        <form
          onSubmit={handleSubmit}
          className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-6 space-y-4"
        >
          {error && (
            <div role="alert" className="flex items-start gap-2 text-xs text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 rounded-lg p-3">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}

          <div className="space-y-1.5">
            <label htmlFor="register-username" className="block text-xs font-semibold text-slate-700 dark:text-slate-300">Username</label>
            <input id="register-username" required minLength={3} maxLength={32} pattern="[a-zA-Z0-9._-]+" autoComplete="username" autoCapitalize="none" value={username} onChange={(e) => setUsername(e.target.value)} disabled={submitting} className={field} placeholder="your name or organization" />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="register-password" className="block text-xs font-semibold text-slate-700 dark:text-slate-300">Password</label>
            <input id="register-password" type="password" required minLength={12} maxLength={256} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} disabled={submitting} className={field} placeholder="At least 12 characters" />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="register-confirmation" className="block text-xs font-semibold text-slate-700 dark:text-slate-300">Confirm password</label>
            <input id="register-confirmation" type="password" required minLength={12} maxLength={256} autoComplete="new-password" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} disabled={submitting} className={field} />
          </div>

          <button type="submit" disabled={submitting || !username.trim() || password.length < 12 || !confirmation} className="w-full flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg bg-brand-600 hover:bg-brand-700 text-white shadow-brand transition disabled:opacity-50 disabled:cursor-not-allowed">
            {submitting ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" /> : <UserPlus className="w-4 h-4" aria-hidden="true" />}
            {submitting ? 'Creating account' : 'Create account'}
          </button>
        </form>

        <button type="button" onClick={() => router.push('/login')} className="w-full mt-3 flex items-center justify-center gap-2 text-sm text-slate-600 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400 transition">
          <Lock className="w-3.5 h-3.5" aria-hidden="true" />
          Already have an account? Sign in
        </button>
      </div>
    </div>
  );
}