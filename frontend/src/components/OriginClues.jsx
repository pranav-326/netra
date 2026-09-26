'use client';

import React from 'react';
import { Compass, Landmark, Phone, Clock, Languages, Globe, Info } from 'lucide-react';

const KIND = {
  iban: { icon: Landmark, label: 'IBAN' },
  swift: { icon: Landmark, label: 'SWIFT' },
  phone: { icon: Phone, label: 'Phone' },
  timezone: { icon: Clock, label: 'Timezone' },
  language: { icon: Languages, label: 'Language' },
  sender_domain: { icon: Globe, label: 'Domain' },
};

const CONFIDENCE = {
  high: 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-900/60',
  medium: 'bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-900/60',
  low: 'bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-900/60',
  undetermined: 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700',
};

const STRENGTH = {
  strong: 'text-emerald-600 dark:text-emerald-400',
  medium: 'text-blue-600 dark:text-blue-400',
  weak: 'text-slate-400',
};

/** Location evidence carried by the email itself (not IP), and what it adds up to. */
export default function OriginClues({ origin }) {
  const clues = origin?.clues || [];
  // Reports stored before origin analysis existed carry none: say so, rather than
  // implying the email was checked and nothing was found.
  const assessment = origin?.assessment || {
    confidence: 'undetermined',
    summary: 'This report predates origin analysis. Submit the email again to check it for location clues.',
  };
  const conflicting = new Set(assessment.conflicting || []);
  const paymentPlaces = [
    ...new Set(clues.filter((c) => c.kind === 'iban' || c.kind === 'swift').map((c) => c.region).filter(Boolean)),
  ];

  return (
    <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Compass className="w-4 h-4 text-slate-700 dark:text-slate-300" />
          <h2 className="text-sm font-bold text-slate-900 dark:text-white">Probable Origin</h2>
        </div>
        <span className={`text-[10px] font-mono font-bold uppercase tracking-wide px-2 py-0.5 rounded border ${CONFIDENCE[assessment.confidence] || CONFIDENCE.undetermined}`}>
          {assessment.confidence === 'undetermined' ? 'Undetermined' : `${assessment.confidence} confidence`}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <div className="text-[10px] text-slate-400 uppercase font-semibold">Sender, probably in</div>
          <div className="text-base font-bold tracking-tight text-slate-900 dark:text-white mt-0.5">
            {assessment.country_name || 'Undetermined'}
          </div>
        </div>
        <div>
          <div className="text-[10px] text-slate-400 uppercase font-semibold">Payment goes to</div>
          <div className="text-base font-bold tracking-tight text-slate-900 dark:text-white mt-0.5">
            {paymentPlaces.length ? paymentPlaces.join(', ') : '—'}
          </div>
        </div>
      </div>
      <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">{assessment.summary}</p>

      {clues.length > 0 && (
        <ul className="space-y-2">
          {clues.map((clue, idx) => {
            const kind = KIND[clue.kind] || { icon: Info, label: clue.kind };
            const Icon = kind.icon;
            const description = `${clue.measures}: ${clue.value}${clue.region ? ` → ${clue.region}` : ''}`;
            const disagrees = conflicting.has(description);
            return (
              <li
                key={`${clue.kind}-${idx}`}
                className={`flex items-start gap-2.5 rounded-lg border p-2.5 ${
                  disagrees
                    ? 'border-amber-200 dark:border-amber-900/60 bg-amber-50/60 dark:bg-amber-950/20'
                    : 'border-slate-100 dark:border-slate-800'
                }`}
              >
                <Icon className="w-3.5 h-3.5 shrink-0 mt-0.5 text-slate-500 dark:text-slate-400" aria-hidden="true" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                      {kind.label}: <span className="font-mono font-normal">{clue.value}</span>
                    </span>
                    <span className={`text-[10px] font-mono font-semibold uppercase shrink-0 ${STRENGTH[clue.strength] || STRENGTH.weak}`}>
                      {clue.strength}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">
                    Locates the {clue.measures}
                    {clue.region ? <> · <span className="text-slate-700 dark:text-slate-300">{clue.region}</span></> : ' · no location'}
                    {disagrees && <span className="text-amber-700 dark:text-amber-400"> · points elsewhere</span>}
                  </div>
                  {clue.note && <div className="text-[11px] text-slate-400 mt-0.5 italic">{clue.note}</div>}
                </div>
              </li>
            );
          })}
        </ul>
      )}

      <div className="pt-2 text-[11px] text-slate-400 flex items-start gap-1.5 border-t border-slate-100 dark:border-slate-800">
        <Info className="w-3.5 h-3.5 shrink-0 mt-0.5 text-slate-400" />
        <span>
          Evidence from the email itself, not IP addresses. Each clue can be forged; a country is named only
          when the clues single one out. This does not affect the risk score.
        </span>
      </div>
    </div>
  );
}
