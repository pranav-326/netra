'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AlertTriangle, CheckCircle2, Loader2, UserPlus } from 'lucide-react';
import { createAnalystUser } from '@/lib/api';
import { getSession } from '@/lib/auth';

const fieldClass =
  'w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm ' +
  'text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-600 disabled:opacity-60';

export default function UserManagementPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState(null);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (getSession()?.role !== 'admin') router.replace('/');
  }, [router]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setMessage(null);
    setError('');
    setSubmitting(true);
    try {
      const created = await createAnalystUser(username.trim(), password);
      setMessage(`Created ${created.username}. They can now sign in and upload EML files.`);
      setUsername('');
      setPassword('');
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <div className="flex items-center gap-2 text-xs font-mono font-medium text-brand-600 dark:text-brand-400">
          <UserPlus className="w-3.5 h-3.5" aria-hidden="true" />
          <span>ADMINISTRATION</span>
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white mt-1">Create an upload user</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
          Analyst accounts can upload email files and view the reports created from their own submissions.
        </p>
      </div>

      <form
        onSubmit={handleSubmit}
        className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-6 space-y-5"
      >
        {error && (
          <div role="alert" className="flex items-start gap-2 text-sm text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 rounded-lg p-3">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}
        {message && (
          <div role="status" className="flex items-start gap-2 text-sm text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-900/60 rounded-lg p-3">
            <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" aria-hidden="true" />
            <span>{message}</span>
          </div>
        )}

        <div className="space-y-1.5">
          <label htmlFor="new-username" className="block text-xs font-semibold text-slate-700 dark:text-slate-300">Username</label>
          <input
            id="new-username"
            required
            minLength={3}
            maxLength={32}
            pattern="[a-zA-Z0-9._-]+"
            autoComplete="off"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            disabled={submitting}
            className={fieldClass}
            placeholder="for example, analyst-jane"
          />
          <p className="text-[11px] text-slate-500 dark:text-slate-400">3-32 letters, numbers, dots, underscores, or hyphens.</p>
        </div>

        <div className="space-y-1.5">
          <label htmlFor="new-password" className="block text-xs font-semibold text-slate-700 dark:text-slate-300">Temporary password</label>
          <input
            id="new-password"
            type="password"
            required
            minLength={12}
            maxLength={256}
            autoComplete="new-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            disabled={submitting}
            className={fieldClass}
            placeholder="At least 12 characters"
          />
        </div>

        <button
          type="submit"
          disabled={submitting || !username.trim() || password.length < 12}
          className="inline-flex items-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg bg-brand-600 hover:bg-brand-700 text-white shadow-brand transition disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {submitting ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" /> : <UserPlus className="w-4 h-4" aria-hidden="true" />}
          {submitting ? 'Creating account' : 'Create analyst account'}
        </button>
      </form>
    </div>
  );
}
