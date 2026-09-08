'use client';

import React, { useId } from 'react';

/**
 * The Netra mark: an open envelope with a watching letter rising from it —
 * नेत्र ("netra", eye) applied to email.
 *
 * Drawn as inline SVG rather than shipped as a raster so it stays crisp at every
 * size, inherits `currentColor` in both themes, and needs no knockout colour: the
 * envelope's flaps are masked behind the letter, leaving that gap genuinely
 * transparent so the mark sits on any background.
 */
export default function NetraMark({ className = 'w-8 h-8', title = 'Netra' }) {
  // Mask ids must be unique per instance or a second render steals the first's mask.
  const maskId = useId();

  return (
    <svg
      viewBox="296 261 663 523"
      className={className}
      role="img"
      aria-label={title}
      fill="none"
    >
      <defs>
        <mask id={maskId}>
          <rect x="296" y="261" width="663" height="523" fill="#fff" />
          {/* Knocks the envelope flaps out from behind the letter, plus a small
              optical gap so the two shapes read as separate strokes. */}
          <path d="M488 265 H768 V515 L628 585 L488 515 Z" fill="#000" />
        </mask>
      </defs>

      <g stroke="currentColor" strokeWidth="42" strokeLinejoin="miter">
        {/* Envelope: sides, base, and the two flaps meeting at the centre V. */}
        <path d="M325 370 V760 H930 V370 L628 610 Z" mask={`url(#${maskId})`} />
        {/* The letter, pointed at the foot. */}
        <path d="M508 285 V505 L628 565 L748 505 V285 Z" />
      </g>

      <g fill="currentColor">
        <circle cx="600" cy="386" r="24" />
        <circle cx="658" cy="386" r="24" />
      </g>
    </svg>
  );
}

/**
 * Mark plus wordmark, matching the logo lockup. Used in the navbar and footer.
 */
export function NetraLockup({ markClassName = 'w-8 h-8', textClassName = 'text-lg' }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <NetraMark className={`${markClassName} text-brand-600 dark:text-brand-400`} />
      <span className={`font-extrabold tracking-tight text-slate-900 dark:text-white ${textClassName}`}>
        <span className="text-brand-600 dark:text-brand-400">ने</span>TRA
      </span>
    </span>
  );
}
