'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, User, Sun, Moon, Laptop } from 'lucide-react';
import { useTheme } from '@/context/ThemeContext';

export default function Navbar() {
  const pathname = usePathname();
  const { theme, setTheme, mounted } = useTheme();

  const navLinks = [
    { name: 'Home', href: '/' },
    { name: 'Analyze Email', href: '/analyze' },
    { name: 'Result', href: '/result' },
    { name: 'Investigations', href: '/investigations' },
    { name: 'Report', href: '/report' },
  ];

  return (
    <header className="sticky top-0 z-50 w-full backdrop-blur-md bg-[#f4f6f8]/90 dark:bg-[#0c1017]/90 border-b border-slate-200/80 dark:border-slate-800 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Left: Brand Identity */}
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-sm shadow-blue-500/20 group-hover:bg-blue-700 transition">
            <Shield className="w-5 h-5 fill-white/20 stroke-white stroke-[2.2]" />
          </div>
          <div className="flex items-center gap-2">
            <span className="font-extrabold text-lg tracking-tight text-slate-900 dark:text-white flex items-center">
              <span className="text-blue-600 dark:text-blue-500 mr-0.5">ने</span>TRA
            </span>
            <span className="text-[11px] font-mono font-medium px-1.5 py-0.5 rounded bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200/70 dark:border-blue-800/60">
              SIH26106
            </span>
          </div>
        </Link>

        {/* Center: Navigation Links */}
        <nav className="hidden md:flex items-center gap-1.5 p-1 rounded-xl bg-slate-200/50 dark:bg-slate-800/50 border border-slate-200/60 dark:border-slate-700/50">
          {navLinks.map((link) => {
            const isActive = pathname === link.href;
            return (
              <Link
                key={link.name}
                href={link.href}
                className={`px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all ${
                  isActive
                    ? 'bg-white dark:bg-slate-900 text-blue-700 dark:text-blue-400 shadow-sm border border-slate-200/80 dark:border-slate-700 font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-white/50 dark:hover:bg-slate-800/60'
                }`}
              >
                {link.name}
              </Link>
            );
          })}
        </nav>

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

          {/* Primary Action Button */}
          <Link
            href="/analyze"
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#0b1b3d] dark:bg-blue-600 hover:bg-[#142858] dark:hover:bg-blue-500 text-white shadow-sm transition flex items-center gap-1.5"
          >
            Analyze Email
          </Link>

          {/* User Profile Button */}
          <button
            aria-label="User Profile"
            className="w-8 h-8 rounded-lg bg-blue-100 dark:bg-slate-800 text-blue-900 dark:text-blue-300 flex items-center justify-center hover:bg-blue-200 dark:hover:bg-slate-700 transition"
          >
            <User className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
}
