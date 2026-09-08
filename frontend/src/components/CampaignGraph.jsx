'use client';

import React, { useEffect, useMemo, useState } from 'react';
import { Network, Loader2, ServerCrash, Mail, Globe, Hash, Link2, Target } from 'lucide-react';
import { fetchEmailSubgraph } from '@/lib/api';

/**
 * Renders the Neo4j attack-infrastructure subgraph for one email.
 *
 * Layout is a deterministic three-ring radial projection rather than a force
 * simulation: the analysed email sits at the centre, the IOCs it touches form the
 * inner ring, and other emails reaching those same IOCs form the outer ring. A fixed
 * layout means the same case always draws the same picture, which matters for a
 * forensic artifact that people compare across runs.
 */

const VIEW_W = 760;
const VIEW_H = 460;
const CX = VIEW_W / 2;
const CY = VIEW_H / 2;
const IOC_RADIUS = 118;
const EMAIL_RADIUS = 200;

const IOC_ICON = { ip: Globe, domain: Globe, url: Link2, sha256: Hash, md5: Hash };

// Verdict palette for sibling email nodes.
const VERDICT_FILL = {
  MALICIOUS: '#ef4444',
  SUSPICIOUS: '#f59e0b',
  BENIGN: '#10b981',
};

/** Places `count` items evenly around a circle, starting at 12 o'clock. */
function radialPositions(count, radius, phase = -Math.PI / 2) {
  if (count === 0) return [];
  return Array.from({ length: count }, (_, i) => {
    const angle = phase + (i / count) * Math.PI * 2;
    return { x: CX + radius * Math.cos(angle), y: CY + radius * Math.sin(angle) };
  });
}

function truncate(text, max) {
  if (!text) return '';
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export default function CampaignGraph({ emailId }) {
  const [graph, setGraph] = useState(null);
  const [loading, setLoading] = useState(false);
  const [hovered, setHovered] = useState(null);

  useEffect(() => {
    if (!emailId) {
      setGraph(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    fetchEmailSubgraph(emailId).then((data) => {
      if (cancelled) return;
      setGraph(data);
      setLoading(false);
    });
    return () => { cancelled = true; };
  }, [emailId]);

  // Compute positions once per graph payload.
  const layout = useMemo(() => {
    if (!graph?.nodes?.length) return null;

    const root = graph.nodes.find((n) => n.kind === 'email' && n.is_root);
    const iocs = graph.nodes.filter((n) => n.kind === 'ioc');
    const siblings = graph.nodes.filter((n) => n.kind === 'email' && !n.is_root);
    const campaign = graph.nodes.find((n) => n.kind === 'campaign');

    const positions = new Map();
    if (root) positions.set(root.id, { x: CX, y: CY });

    radialPositions(iocs.length, IOC_RADIUS).forEach((pos, i) => positions.set(iocs[i].id, pos));
    // Offset the outer ring by half a step so sibling nodes sit between IOC spokes.
    const phase = -Math.PI / 2 + (siblings.length ? Math.PI / siblings.length : 0);
    radialPositions(siblings.length, EMAIL_RADIUS, phase).forEach((pos, i) =>
      positions.set(siblings[i].id, pos)
    );
    if (campaign) positions.set(campaign.id, { x: CX, y: CY - EMAIL_RADIUS - 26 });

    return { root, iocs, siblings, campaign, positions };
  }, [graph]);

  if (!emailId) return null;

  if (loading) {
    return (
      <GraphShell>
        <div className="flex items-center justify-center gap-2 py-16 text-xs text-slate-500">
          <Loader2 className="w-4 h-4 animate-spin" />
          Querying Neo4j for shared infrastructure…
        </div>
      </GraphShell>
    );
  }

  if (graph?.unavailable) {
    return (
      <GraphShell>
        <div className="flex items-start gap-3 py-8 px-2 text-xs text-slate-500 dark:text-slate-400">
          <ServerCrash className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold text-slate-700 dark:text-slate-300">Graph unavailable</div>
            <p className="mt-0.5">
              {graph.reason} Correlation data cannot be shown — this is not the same as
              &ldquo;no shared infrastructure found&rdquo;.
            </p>
          </div>
        </div>
      </GraphShell>
    );
  }

  if (!graph?.found || !layout?.root) {
    return (
      <GraphShell>
        <p className="py-8 px-2 text-xs text-slate-500 dark:text-slate-400">
          This email has no node in the correlation graph yet. Graph correlation runs as stage 6
          of the pipeline; a report produced before that stage completed will not appear here.
        </p>
      </GraphShell>
    );
  }

  const { root, iocs, siblings, campaign, positions } = layout;
  const stats = graph.stats || {};
  const bridgeIocs = iocs.filter((n) => (n.shared_by || 1) > 1);

  return (
    <GraphShell
      subtitle={
        siblings.length > 0
          ? `Shares ${bridgeIocs.length} indicator${bridgeIocs.length === 1 ? '' : 's'} with ${siblings.length} other email${siblings.length === 1 ? '' : 's'}`
          : 'No other ingested email reaches this infrastructure'
      }
    >
      {/* Headline claim — the thing a rule engine alone cannot say */}
      <div className="grid grid-cols-3 gap-3 mb-4">
        <Stat label="Related emails" value={siblings.length} accent={siblings.length > 0} />
        <Stat label="Shared indicators" value={bridgeIocs.length} accent={bridgeIocs.length > 0} />
        <Stat label="Total IOC nodes" value={iocs.length} />
      </div>

      {campaign && (
        <div className="mb-4 rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 px-3 py-2 flex items-center gap-2.5">
          <Target className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0" />
          <div className="text-xs min-w-0">
            <span className="font-bold text-red-800 dark:text-red-300">Campaign cluster: </span>
            <span className="text-red-700 dark:text-red-400">{campaign.label}</span>
            <span className="font-mono text-[10px] text-red-500 ml-2">{campaign.campaign_id}</span>
          </div>
        </div>
      )}

      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/40 overflow-x-auto">
        <svg
          viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
          className="w-full min-w-[560px]"
          role="img"
          aria-label={`Attack infrastructure graph: ${siblings.length} related emails sharing ${bridgeIocs.length} indicators`}
        >
          {/* Edges first so nodes paint over them */}
          <g>
            {graph.edges.map((edge, idx) => {
              const a = positions.get(edge.source);
              const b = positions.get(edge.target);
              if (!a || !b) return null;

              const isRootEdge = edge.source === root.id;
              const isHighlighted =
                hovered && (edge.source === hovered || edge.target === hovered);

              return (
                <line
                  key={`${edge.source}-${edge.target}-${edge.relation}-${idx}`}
                  x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                  stroke={isHighlighted ? '#3b82f6' : isRootEdge ? '#94a3b8' : '#cbd5e1'}
                  strokeWidth={isHighlighted ? 2 : isRootEdge ? 1.4 : 0.9}
                  strokeOpacity={hovered && !isHighlighted ? 0.15 : isRootEdge ? 0.85 : 0.45}
                  strokeDasharray={edge.relation === 'SHARES' ? '3 3' : undefined}
                />
              );
            })}
          </g>

          {/* Sibling emails — the outer ring */}
          <g>
            {siblings.map((node) => {
              const pos = positions.get(node.id);
              if (!pos) return null;
              const fill = VERDICT_FILL[node.verdict] || '#94a3b8';
              const dim = hovered && hovered !== node.id;
              return (
                <g
                  key={node.id}
                  onMouseEnter={() => setHovered(node.id)}
                  onMouseLeave={() => setHovered(null)}
                  style={{ cursor: 'pointer', opacity: dim ? 0.35 : 1 }}
                >
                  <circle cx={pos.x} cy={pos.y} r={9} fill={fill} stroke="#fff" strokeWidth={1.5} />
                  <text
                    x={pos.x} y={pos.y - 15}
                    textAnchor="middle"
                    className="fill-slate-500 dark:fill-slate-400"
                    style={{ fontSize: 8.5, fontFamily: 'ui-monospace, monospace' }}
                  >
                    {node.risk_score ?? '—'}
                  </text>
                </g>
              );
            })}
          </g>

          {/* IOC nodes — the inner ring. Bridging IOCs are drawn larger. */}
          <g>
            {iocs.map((node) => {
              const pos = positions.get(node.id);
              if (!pos) return null;
              const sharedBy = node.shared_by || 1;
              const isBridge = sharedBy > 1;
              const r = isBridge ? 11 : 7;
              const dim = hovered && hovered !== node.id;

              return (
                <g
                  key={node.id}
                  onMouseEnter={() => setHovered(node.id)}
                  onMouseLeave={() => setHovered(null)}
                  style={{ cursor: 'pointer', opacity: dim ? 0.35 : 1 }}
                >
                  <rect
                    x={pos.x - r} y={pos.y - r} width={r * 2} height={r * 2} rx={3}
                    fill={isBridge ? '#f97316' : '#64748b'}
                    stroke="#fff" strokeWidth={1.5}
                  />
                  <text
                    x={pos.x} y={pos.y + r + 11}
                    textAnchor="middle"
                    className="fill-slate-600 dark:fill-slate-300"
                    style={{ fontSize: 9, fontFamily: 'ui-monospace, monospace' }}
                  >
                    {truncate(node.label, 22)}
                  </text>
                  {isBridge && (
                    <text
                      x={pos.x} y={pos.y + 3.5}
                      textAnchor="middle"
                      fill="#fff"
                      style={{ fontSize: 9, fontWeight: 700, fontFamily: 'ui-monospace, monospace' }}
                    >
                      {sharedBy}
                    </text>
                  )}
                </g>
              );
            })}
          </g>

          {/* Root email — the message under analysis */}
          <g>
            <circle cx={CX} cy={CY} r={22} fill="#1d4ed8" stroke="#fff" strokeWidth={3} />
            <circle cx={CX} cy={CY} r={29} fill="none" stroke="#1d4ed8" strokeWidth={1} strokeOpacity={0.35} />
            <text
              x={CX} y={CY + 4}
              textAnchor="middle" fill="#fff"
              style={{ fontSize: 11, fontWeight: 700, fontFamily: 'ui-monospace, monospace' }}
            >
              {root.risk_score ?? '?'}
            </text>
            <text
              x={CX} y={CY + 46}
              textAnchor="middle"
              className="fill-slate-700 dark:fill-slate-200"
              style={{ fontSize: 10, fontWeight: 600 }}
            >
              {truncate(root.label, 44)}
            </text>
          </g>
        </svg>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 mt-3 text-[10px] text-slate-500 dark:text-slate-400">
        <LegendItem swatch={<span className="w-3 h-3 rounded-full bg-blue-700 inline-block" />} text="This email" />
        <LegendItem swatch={<span className="w-3 h-3 rounded-sm bg-orange-500 inline-block" />} text="Shared indicator (number = emails reaching it)" />
        <LegendItem swatch={<span className="w-3 h-3 rounded-sm bg-slate-500 inline-block" />} text="Indicator unique to this email" />
        <LegendItem swatch={<span className="w-3 h-3 rounded-full bg-red-500 inline-block" />} text="Related email (colour = verdict, label = score)" />
      </div>

      {stats.truncated && (
        <p className="text-[10px] text-slate-400 mt-2">
          Graph truncated for legibility — this cluster has more members than are drawn.
        </p>
      )}

      <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-3 leading-relaxed">
        Built by the correlation service (stage 6) in Neo4j. Each edge is a real relationship
        written when an email was ingested; nothing here is inferred at render time.
      </p>
    </GraphShell>
  );
}

function GraphShell({ children, subtitle }) {
  return (
    <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 shadow-sm overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-blue-600 dark:text-blue-400" />
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">
            Attack Infrastructure Graph
          </h3>
        </div>
        {subtitle && (
          <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">{subtitle}</p>
        )}
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

function Stat({ label, value, accent = false }) {
  return (
    <div className={`rounded-lg border p-3 ${
      accent
        ? 'border-blue-200 dark:border-blue-900/60 bg-blue-50/60 dark:bg-blue-950/30'
        : 'border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/40'
    }`}>
      <div className={`text-xl font-black font-mono leading-none ${
        accent ? 'text-blue-600 dark:text-blue-400' : 'text-slate-700 dark:text-slate-300'
      }`}>
        {value}
      </div>
      <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold mt-1">
        {label}
      </div>
    </div>
  );
}

function LegendItem({ swatch, text }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      {swatch}
      {text}
    </span>
  );
}
