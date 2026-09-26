'use client';

import React, { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { User, Sun, Moon, Laptop, Menu, X, LogOut } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';
import NetraMark from '@/components/brand/NetraMark';
import { getSession, onSessionChange, signOut } from '@/lib/auth';

export default function Navbar() {
  const pathname = usePathname();
  const router = useRouter();
  const { theme, setTheme, mounted } = useTheme();
  const [menuOpen, setMenuOpen] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
  const [session, setSession] = useState(null);
  const accountRef = useRef(null);

  useEffect(() => {
    const sync = () => setSession(getSession());
    sync();
    return onSessionChange(sync);
  }, []);

  // Close the menus on navigation.
  useEffect(() => { setMenuOpen(false); setAccountOpen(false); }, [pathname]);

  // Close the account menu on an outside click or Escape.
  useEffect(() => {
    if (!accountOpen) return undefined;
    const onClick = (e) => { if (!accountRef.current?.contains(e.target)) setAccountOpen(false); };
    const onKey = (e) => { if (e.key === 'Escape') setAccountOpen(false); };
    document.addEventListener('mousedown', onClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [accountOpen]);

  const handleSignOut = () => {
    signOut();
    router.replace('/login');
  };

  const navLinks = [
    { name: 'Home', href: '/' },
    { name: 'Analyze Email', href: '/analyze' },
    { name: 'Result', href: '/result' },
    { name: 'Investigations', href: '/investigations' },
    { name: 'Report', href: '/report' },
  ];

  return (
    <header className="sticky top-0 z-50 w-full backdrop-blur-md bg-[#f4f6f8]/85 dark:bg-[#0c1017]/85 border-b border-slate-200/80 dark:border-slate-800 transition-colors">
      {/* Brand hairline */}
      <div className="h-0.5 w-full bg-gradient-to-r from-brand-600 via-brand-400 to-brand-600 opacity-90" />
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Left: Brand Identity */}
        <Link
          href="/"
          className="flex items-center gap-2.5 group rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-600 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-slate-950"
          aria-label="Netra home"
        >
          <NetraMark className="w-8 h-8 text-brand-600 dark:text-brand-400 group-hover:text-brand-700 dark:group-hover:text-brand-300 transition-colors" />
          <span className="flex items-center gap-2">
            <span className="font-extrabold text-lg tracking-tight text-slate-900 dark:text-white">
              <span className="text-brand-600 dark:text-brand-400">ने</span>TRA
            </span>
            <span className="hidden sm:inline text-[11px] font-mono font-medium px-1.5 py-0.5 rounded bg-brand-50 dark:bg-brand-950/60 text-brand-700 dark:text-brand-300 border border-brand-200/70 dark:border-brand-800/60">
              SIH26106
            </span>
          </span>
        </Link>

        {/* Center: Navigation Links (signed-in only) */}
        {session && (
        <nav className="hidden md:flex items-center gap-1.5 p-1 rounded-xl bg-slate-200/50 dark:bg-slate-800/50 border border-slate-200/60 dark:border-slate-700/50">
          {navLinks.map((link) => {
            const isActive = pathname === link.href;
            return (
              <Link
                key={link.name}
                href={link.href}
                className={`px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all ${
                  isActive
                    ? 'bg-white dark:bg-slate-900 text-brand-700 dark:text-brand-300 shadow-sm border border-slate-200/80 dark:border-slate-700 font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-white/50 dark:hover:bg-slate-800/60'
                }`}
              >
                {link.name}
              </Link>
            );
          })}
        </nav>
        )}

        {/* Right: Theme Switcher & Actions */}
        <div className="flex items-center gap-3">
          {/* Segmented Theme Switcher */}
          {mounted && (
            <div className="flex items-center p-0.5 rounded-lg bg-slate-200/60 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/80 text-[11px] font-medium text-slate-600 dark:text-slate-400">
              <button
                onClick={() => setTheme('light')}
                className={`px-2 py-1 rounded-md flex items-center gap-1 transition ${
                  theme === 'light'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs font-semibold'
                    : 'hover:text-slate-900 dark:hover:text-white'
                }`}
                title="Light mode"
              >
                <Sun className="w-3 h-3" />
                <span>Light</span>
              </button>
              <button
                onClick={() => setTheme('dark')}
                className={`px-2 py-1 rounded-md flex items-center gap-1 transition ${
                  theme === 'dark'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs font-semibold'
                    : 'hover:text-slate-900 dark:hover:text-white'
                }`}
                title="Dark mode"
              >
                <Moon className="w-3 h-3" />
                <span>Dark</span>
              </button>
              <button
                onClick={() => setTheme('sys')}
                className={`px-2 py-1 rounded-md flex items-center gap-1 transition ${
                  theme === 'sys'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs font-semibold'
                    : 'hover:text-slate-900 dark:hover:text-white'
                }`}
                title="System preference"
              >
                <Laptop className="w-3 h-3" />
                <span>Sys</span>
              </button>
            </div>
          )}

          {session && (
          <>
          {/* Primary Action Button */}
          <Link
            href="/analyze"
            className="hidden sm:flex px-4 py-2 text-xs font-semibold rounded-lg bg-brand-600 hover:bg-brand-700 text-white shadow-brand transition items-center gap-1.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-600 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-slate-950"
          >
            Analyze Email
          </Link>

          {/* Mobile menu toggle — below md the link bar is hidden */}
          <button
            onClick={() => setMenuOpen((open) => !open)}
            aria-label={menuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            aria-expanded={menuOpen}
            className="md:hidden w-8 h-8 rounded-lg bg-slate-200/60 dark:bg-slate-800/60 text-slate-700 dark:text-slate-300 flex items-center justify-center hover:bg-slate-300/60 dark:hover:bg-slate-700 transition"
          >
            {menuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>

          {/* Account menu */}
          <div className="relative" ref={accountRef}>
            <button
              onClick={() => setAccountOpen((open) => !open)}
              aria-label={`Account: ${session.username}`}
              aria-haspopup="menu"
              aria-expanded={accountOpen}
              className="w-8 h-8 rounded-lg bg-brand-50 dark:bg-slate-800 text-brand-700 dark:text-brand-300 flex items-center justify-center hover:bg-brand-100 dark:hover:bg-slate-700 transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-600"
            >
              <User className="w-4 h-4" />
            </button>
            {accountOpen && (
              <div
                role="menu"
                className="absolute right-0 mt-2 w-56 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-lg p-1.5"
              >
                <div className="px-3 py-2 border-b border-slate-100 dark:border-slate-800 mb-1">
                  <div className="text-sm font-semibold text-slate-900 dark:text-white truncate">{session.username}</div>
                  <div className="mt-1 inline-block text-[10px] font-mono font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded bg-brand-50 dark:bg-brand-950/60 text-brand-700 dark:text-brand-300 border border-brand-200/70 dark:border-brand-800/60">
                    {session.role}
                  </div>
                </div>
                <button
                  role="menuitem"
                  onClick={handleSignOut}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                >
                  <LogOut className="w-4 h-4" aria-hidden="true" />
                  Sign out
                </button>
              </div>
            )}
          </div>
          </>
          )}
        </div>
      </div>

      {/* Mobile navigation panel */}
      {session && menuOpen && (
        <nav className="md:hidden border-t border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-950/95 backdrop-blur-md px-4 py-3 space-y-1">
          {navLinks.map((link) => {
            const isActive = pathname === link.href;
            return (
              <Link
                key={link.name}
                href={link.href}
                className={`block px-3 py-2 rounded-lg text-sm font-medium transition ${
                  isActive
                    ? 'bg-brand-50 dark:bg-brand-950/50 text-brand-700 dark:text-brand-300 font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                {link.name}
              </Link>
            );
          })}
          <Link
            href="/analyze"
            className="block mt-2 px-3 py-2 rounded-lg text-sm font-semibold bg-brand-600 hover:bg-brand-700 text-white text-center transition"
          >
            Analyze Email
          </Link>
        </nav>
      )}
    </header>
  );
}
