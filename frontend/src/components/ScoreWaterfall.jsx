'use client';

import React from 'react';
import { Scale, Info, AlertTriangle } from 'lucide-react';

/**
 * Waterfall chart of the rule contributions that produced a risk score.
 *
 * Every bar is one rule the backend scorer fired, and the running total is a literal
 * cumulative sum of `points`. Nothing here is derived, weighted, or approximated on
 * the client — Netra's score IS this sum, which is what makes the explanation exact
 * rather than an attribution estimate like SHAP or LIME.
 */

// Vector colours, held as explicit light/dark pairs so the chart reads in both themes.
const CATEGORY_STYLE = {
  attachment: { bar: 'bg-red-500', dot: 'bg-red-500', text: 'text-red-600 dark:text-red-400', label: 'Attachment' },
  url: { bar: 'bg-orange-500', dot: 'bg-orange-500', text: 'text-orange-600 dark:text-orange-400', label: 'URL / Domain' },
  content: { bar: 'bg-amber-500', dot: 'bg-amber-500', text: 'text-amber-600 dark:text-amber-400', label: 'Content / BEC' },
  header: { bar: 'bg-blue-500', dot: 'bg-blue-500', text: 'text-blue-600 dark:text-blue-400', label: 'Header / Auth' },
  // The learned layer gets a distinct colour: an analyst should see at a glance how
  // much of a score came from the model rather than from a hand-written rule.
  ml: { bar: 'bg-violet-500', dot: 'bg-violet-500', text: 'text-violet-600 dark:text-violet-400', label: 'Learned model' },
};

const FALLBACK_STYLE = {
  bar: 'bg-slate-400',
  dot: 'bg-slate-400',
  text: 'text-slate-600 dark:text-slate-400',
  label: 'Other',
};

const styleFor = (category) => CATEGORY_STYLE[category] || FALLBACK_STYLE;

// Verdict boundaries, mirroring MALICIOUS_THRESHOLD / SUSPICIOUS_THRESHOLD in scorer.py.
const SUSPICIOUS_AT = 21;
const MALICIOUS_AT = 61;

export default function ScoreWaterfall({ contributions = [], finalScore = 0, rawScore = null, verdict = '' }) {
  if (!contributions.length) {
    return (
      <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm p-5">
        <div className="flex items-center gap-2 mb-2">
          <Scale className="w-4 h-4 text-slate-400" />
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">Score Explanation</h3>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          No scoring rules fired for this message. A score of {finalScore} means every check the
          engine ran came back clean — not that the message was skipped.
        </p>
      </div>
    );
  }

  const raw = rawScore ?? contributions.reduce((sum, c) => sum + c.points, 0);
  const wasClamped = raw > 100;

  // The waterfall is drawn against the raw sum so a clamped score still shows every
  // rule at its true width, with the ceiling marked separately.
  const axisMax = Math.max(raw, 100);

  const mlCount = contributions.filter((c) => c.category === 'ml').length;
  const ruleCount = contributions.length - mlCount;

  let running = 0;
  const steps = contributions.map((c) => {
    const start = running;
    running += c.points;
    return { ...c, start, end: running };
  });

  return (
    <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Scale className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">
              How this score was reached
            </h3>
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
            {ruleCount} rule{ruleCount === 1 ? '' : 's'} fired{mlCount ? ' + learned model' : ''} · deterministic and auditable by design
          </p>
        </div>
        <div className="text-right shrink-0">
          <div className="text-2xl font-black font-mono leading-none text-slate-900 dark:text-white">
            {finalScore}
            <span className="text-sm text-slate-400 font-bold">/100</span>
          </div>
          {verdict && (
            <div className="text-[10px] font-mono font-bold text-slate-500 dark:text-slate-400 mt-1">
              {verdict}
            </div>
          )}
        </div>
      </div>

      <div className="p-5 space-y-4">
        {/* Waterfall rows: each bar starts where the previous one ended. */}
        <div className="space-y-2.5">
          {steps.map((step) => {
            const style = styleFor(step.category);
            // A negative contribution (only the model can produce one) draws backwards
            // from the running total rather than off the left edge of the track.
            const barStart = Math.min(step.start, step.end);
            const offsetPct = (barStart / axisMax) * 100;
            const widthPct = (Math.abs(step.points) / axisMax) * 100;

            return (
              <div key={step.rule_id} className="group">
                <div className="flex items-baseline justify-between gap-3 mb-1">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${style.dot}`} />
                    <span className="text-xs font-medium text-slate-800 dark:text-slate-200 truncate">
                      {step.label}
                    </span>
                    <span className="font-mono text-[10px] text-slate-400 shrink-0 hidden sm:inline">
                      {step.rule_id}
                    </span>
                  </div>
                  <div className="flex items-baseline gap-2 shrink-0 font-mono text-[11px]">
                    <span className={`font-bold ${style.text}`}>
                      {step.points >= 0 ? `+${step.points}` : step.points}
                    </span>
                    <span className="text-slate-400 w-8 text-right">{step.end}</span>
                  </div>
                </div>

                {/* Floating bar: offset by the running total, width by this rule's points. */}
                <div className="h-2.5 w-full rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                  <div className="h-full flex" style={{ paddingLeft: `${offsetPct}%` }}>
                    <div
                      className={`h-full rounded-full ${style.bar} transition-all`}
                      style={{ width: `${widthPct}%` }}
                    />
                  </div>
                </div>

                {step.evidence && (
                  <div className="text-[10px] text-slate-500 dark:text-slate-500 mt-1 pl-3.5 leading-snug break-words">
                    {step.evidence}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Total row */}
        <div className="pt-3 border-t border-slate-200 dark:border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-slate-700 dark:text-slate-300">
              Sum of contributions
            </span>
            <span className="font-mono font-bold text-slate-900 dark:text-white">{raw}</span>
          </div>

          {wasClamped && (
            <div className="flex items-start gap-2 text-[11px] text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/50 rounded-lg p-2.5">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" />
              <span>
                Contributions summed to <span className="font-mono font-bold">{raw}</span>, above the
                scale ceiling. The score is clamped to <span className="font-mono font-bold">100</span> —
                the excess is shown rather than hidden, because a message can trip far more evidence
                than the top of the scale can express.
              </span>
            </div>
          )}

          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-slate-700 dark:text-slate-300">Final risk score</span>
            <span className="font-mono font-black text-blue-600 dark:text-blue-400">{finalScore}/100</span>
          </div>
        </div>

        {/* Verdict scale, so the threshold that produced the label is visible too. */}
        <div className="space-y-1.5">
          <div className="relative h-6">
            <div className="absolute inset-x-0 top-2 h-2 rounded-full overflow-hidden flex">
              <div className="bg-emerald-400/70 dark:bg-emerald-600/60" style={{ width: `${SUSPICIOUS_AT}%` }} />
              <div className="bg-amber-400/70 dark:bg-amber-600/60" style={{ width: `${MALICIOUS_AT - SUSPICIOUS_AT}%` }} />
              <div className="bg-red-400/70 dark:bg-red-600/60" style={{ width: `${100 - MALICIOUS_AT}%` }} />
            </div>
            <div
              className="absolute top-0 w-0.5 h-6 bg-slate-900 dark:bg-white rounded"
              style={{ left: `calc(${Math.min(finalScore, 100)}% - 1px)` }}
              title={`Final score: ${finalScore}`}
            />
          </div>
          <div className="flex justify-between font-mono text-[10px] text-slate-400">
            <span>0 · BENIGN</span>
            <span>{SUSPICIOUS_AT} · SUSPICIOUS</span>
            <span>{MALICIOUS_AT} · MALICIOUS</span>
            <span>100</span>
          </div>
        </div>

        {steps.some((step) => step.category === 'ml') && (
          <div className="text-[11px] text-violet-700 dark:text-violet-300 bg-violet-50 dark:bg-violet-950/30 border border-violet-200 dark:border-violet-900/50 rounded-lg p-2.5">
            One bar comes from the learned classifier. It is capped and additive — a second
            opinion, never an override — and decomposes into the same kind of per-feature
            terms as every rule above.
          </div>
        )}

        {/* The design claim, stated plainly. */}
        <div className="flex items-start gap-2 text-[11px] text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-950/50 border border-slate-200 dark:border-slate-800 rounded-lg p-3">
          <Info className="w-3.5 h-3.5 shrink-0 mt-px text-slate-400" />
          <span>
            Netra scores with a deterministic rule engine, so this chart is the computation
            itself — not a post-hoc approximation of a black-box classifier. The same email
            always yields the same score, every point traces to a named rule, and an analyst
            can contest any single line of it.
          </span>
        </div>
      </div>
    </div>
  );
}
