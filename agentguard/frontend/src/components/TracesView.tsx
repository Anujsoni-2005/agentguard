import React, { useState } from 'react';
import { ActiveRunData } from '../types';

interface TracesViewProps {
  runs: ActiveRunData[];
  onSelectRun: (id: string) => void;
}

export const TracesView: React.FC<TracesViewProps> = ({ runs, onSelectRun }) => {
  const [selectedRunId, setSelectedRunId] = useState<string>(runs[0]?.id || '');
  const [searchQuery, setSearchQuery] = useState('');

  const activeRun = runs.find((r) => r.id === selectedRunId) || runs[0];

  return (
    <main className="flex-1 px-margin py-8 max-w-6xl w-full mx-auto space-y-6">
      {/* Upcoming notice */}
      <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-surface-container border border-outline-variant/50">
        <span className="text-[10px] font-bold px-2 py-1 rounded bg-outline-variant/30 text-on-surface-variant border border-outline-variant/50 tracking-widest shrink-0">U UPCOMING</span>
        <p className="text-body-sm font-body-sm text-on-surface-variant">
          Execution Traces &mdash; UI preview only. The <code className="font-code-sm text-code-sm">/v1/ledger/verify</code> endpoint has a broken dependency injection. Trace data shown is from active run state only.
        </p>
      </div>
      <div className="flex flex-col md:flex-row md:items-baseline justify-between gap-4">
        <div>
          <h2 className="text-headline-lg font-headline-lg text-on-surface tracking-tight text-3xl font-serif">
            Execution Traces
          </h2>
          <p className="text-body-lg font-body-lg text-on-surface-variant mt-1.5 font-light">
            Immutable chronological telemetry ledger, tool inputs/outputs, and latency breakdowns.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={selectedRunId}
            onChange={(e) => setSelectedRunId(e.target.value)}
            className="px-3 py-1.5 rounded-lg border border-outline-variant/60 bg-surface-container-lowest text-body-sm font-body-sm text-on-surface focus:outline-none cursor-pointer"
          >
            {runs.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name} ({r.agentId})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Trace overview & stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant/40">
          <div className="text-label-sm font-label-sm text-on-surface-variant uppercase">
            Trace Session
          </div>
          <div className="font-code-md text-code-md font-semibold text-on-surface mt-1">
            aud_8492_99a
          </div>
        </div>
        <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant/40">
          <div className="text-label-sm font-label-sm text-on-surface-variant uppercase">
            Span Count
          </div>
          <div className="font-code-md text-code-md font-semibold text-on-surface mt-1">
            18 spans
          </div>
        </div>
        <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant/40">
          <div className="text-label-sm font-label-sm text-on-surface-variant uppercase">
            Average Latency
          </div>
          <div className="font-code-md text-code-md font-semibold text-secondary mt-1">
            820ms
          </div>
        </div>
        <div className="bg-surface-container-lowest p-4 rounded-xl border border-outline-variant/40">
          <div className="text-label-sm font-label-sm text-on-surface-variant uppercase">
            Anomalies / Denials
          </div>
          <div className="font-code-md text-code-md font-semibold text-error mt-1">
            1 Interception
          </div>
        </div>
      </div>

      {/* Raw Trace Stream Ledger */}
      <div className="bg-surface-container-lowest rounded-xl border border-outline-variant/40 p-6 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-surface-container-high">
          <h3 className="text-headline-sm font-headline-sm text-on-surface font-serif">
            Structured Event Stream
          </h3>
          <input
            type="text"
            placeholder="Filter trace events..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="px-3 py-1 bg-surface-container-low border border-outline-variant/40 rounded-lg text-body-sm font-body-sm w-64 focus:outline-none"
          />
        </div>

        <div className="space-y-3 font-code-sm text-code-sm">
          {activeRun?.steps.map((st) => (
            <div
              key={st.id}
              className="p-3 rounded-lg bg-surface-container-low border border-outline-variant/30 flex flex-col gap-1.5"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
                      st.type === 'ASK_HUMAN'
                        ? 'bg-[#FBF4E8] text-[#805200] border border-[#EACD9B]'
                        : st.type === 'DENY'
                        ? 'bg-[#F9EBE9] text-[#B34A3E] border border-error/20'
                        : 'bg-[#E8F0EA] text-[#2F5B3D] border border-secondary/30'
                    }`}
                  >
                    {st.type}
                  </span>
                  <span className="font-medium text-on-surface">{st.title}</span>
                </div>
                <span className="text-on-surface-variant/70">{st.timeAgo}</span>
              </div>
              {st.reasoning && (
                <div className="text-on-surface-variant text-body-sm italic pl-2 border-l-2 border-outline-variant/40">
                  {st.reasoning}
                </div>
              )}
              {st.payloadCode && (
                <pre className="p-2 bg-surface-container-lowest rounded border border-outline-variant/30 text-on-surface overflow-x-auto text-[11px]">
                  {st.payloadCode}
                </pre>
              )}
            </div>
          ))}
        </div>
      </div>
    </main>
  );
};
