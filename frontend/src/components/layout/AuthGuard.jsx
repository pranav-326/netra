'use client';

import React, { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { Loader2 } from 'lucide-react';
import { getSession, onSessionChange } from '@/lib/auth';

const PUBLIC_PATHS = new Set(['/login', '/register']);

/** Renders a page only for a signed-in user; everyone else is sent to /login. */
export default function AuthGuard({ children }) {
  const pathname = usePathname();
  const router = useRouter();
  const [signedIn, setSignedIn] = useState(null); // null until checked on the client
  const isPublic = PUBLIC_PATHS.has(pathname);

  useEffect(() => {
    const check = () => setSignedIn(Boolean(getSession()));
    check();
    return onSessionChange(check);
  }, []);

  useEffect(() => {
    if (signedIn === false && !isPublic) {
      const next = window.location.pathname + window.location.search;
      router.replace(`/login?next=${encodeURIComponent(next)}`);
    }
  }, [signedIn, isPublic, router]);

  if (isPublic || signedIn) return children;

  return (
    <div className="flex items-center justify-center gap-2 py-24 text-sm text-slate-500 dark:text-slate-400">
      <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
      Checking your session…
    </div>
  );
}
