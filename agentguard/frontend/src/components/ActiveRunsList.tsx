import React from 'react';
import { ActiveRunData } from '../types';

interface ActiveRunsListProps {
  runs: ActiveRunData[];
  onSelectRun: (runId: string) => void;
  onNewRun: () => void;
}

export const ActiveRunsList: React.FC<ActiveRunsListProps> = ({
  runs,
  onSelectRun,
  onNewRun
}) => {
  return (
    <main className="flex-1 px-margin py-8 max-w-6xl w-full mx-auto">
      <div className="flex items-baseline justify-between mb-8">
        <div>
          <h2 className="text-headline-lg font-headline-lg text-on-surface tracking-tight text-3xl font-serif">
            Active Runs
          </h2>
          <p className="text-body-lg font-body-lg text-on-surface-variant mt-1.5 font-light">
            Real-time telemetry and supervisory control across autonomous agent pipelines.
          </p>
        </div>
        <button
          onClick={onNewRun}
          className="px-4 py-2 rounded-lg bg-primary-container text-on-primary-container font-label-md text-label-md flex items-center gap-2 shadow-sm hover:opacity-95 transition-all cursor-pointer"
        >
          <span className="material-symbols-outlined text-base">add</span>
          <span>Initialize Run</span>
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {runs.map((r) => {
          const isPaused = r.status === 'PAUSED (AWAITING INPUT)';
          const isRunning = r.status === 'RUNNING';
          const isHalted = r.status === 'HALTED';

          return (
            <div
              key={r.id}
              onClick={() => onSelectRun(r.id)}
              className="bg-surface-container-lowest rounded-xl border border-outline-variant/40 p-6 shadow-[0_2px_12px_-2px_rgba(42,42,40,0.03)] hover:border-primary/40 transition-all cursor-pointer group"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-3 border-b border-surface-container-high">
                <div className="flex items-center gap-3">
                  <span className="font-code-md text-code-md font-semibold text-on-surface group-hover:text-primary transition-colors">
                    {r.name}
                  </span>
                  <span className="w-1 h-1 rounded-full bg-outline-variant"></span>
                  <span className="text-label-sm font-label-sm text-on-surface-variant">
                    {r.agentId}
                  </span>
                  <span className="w-1 h-1 rounded-full bg-outline-variant"></span>
                  <span className="text-label-sm font-label-sm text-on-surface-variant">
                    {r.model}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  {isPaused && (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[#FBF4E8] border border-[#EACD9B] text-[#805200] text-label-sm font-label-sm">
                      <span className="w-2 h-2 rounded-full bg-[#C98A2C] pulse-amber"></span>
                      <span>PAUSED (AWAITING INPUT)</span>
                    </span>
                  )}
                  {isRunning && (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-secondary-container/40 border border-secondary/30 text-secondary text-label-sm font-label-sm">
                      <span className="w-2 h-2 rounded-full bg-secondary animate-pulse"></span>
                      <span>RUNNING</span>
                    </span>
                  )}
                  {isHalted && (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-error-container/40 border border-error/30 text-error text-label-sm font-label-sm">
                      <span className="w-2 h-2 rounded-full bg-error"></span>
                      <span>HALTED</span>
                    </span>
                  )}
                  {r.status === 'COMPLETED' && (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-surface-container text-on-surface-variant text-label-sm font-label-sm">
                      <span className="w-2 h-2 rounded-full bg-secondary"></span>
                      <span>COMPLETED</span>
                    </span>
                  )}
                </div>
              </div>

              <div className="mt-3">
                <h3 className="text-body-lg font-body-lg font-medium text-on-surface font-serif">
                  {r.objective}
                </h3>
                <p className="text-body-sm font-body-sm text-on-surface-variant mt-1">
                  {r.objectiveDescription}
                </p>
              </div>

              {/* Progress & metrics row */}
              <div className="mt-4 pt-3 flex flex-wrap items-center justify-between gap-4 border-t border-outline-variant/30 text-body-sm font-body-sm">
                <div className="flex items-center gap-6">
                  <div>
                    <span className="text-label-sm font-label-sm text-on-surface-variant/70 uppercase">
                      Steps
                    </span>
                    <div className="font-code-sm text-code-sm font-medium text-on-surface">
                      {r.stepsTaken} / {r.maxSteps}
                    </div>
                  </div>
                  <div>
                    <span className="text-label-sm font-label-sm text-on-surface-variant/70 uppercase">
                      Cost
                    </span>
                    <div className="font-code-sm text-code-sm font-medium text-on-surface">
                      ${r.computeCost.toFixed(2)} / ${r.computeCap.toFixed(2)}
                    </div>
                  </div>
                  <div>
                    <span className="text-label-sm font-label-sm text-on-surface-variant/70 uppercase">
                      Tokens
                    </span>
                    <div className="font-code-sm text-code-sm font-medium text-on-surface">
                      {r.tokensProcessed.toLocaleString()}
                    </div>
                  </div>
                  <div>
                    <span className="text-label-sm font-label-sm text-on-surface-variant/70 uppercase">
                      Runtime
                    </span>
                    <div className="font-code-sm text-code-sm font-medium text-on-surface">
                      {r.runtimeFormatted}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-label-md font-label-md text-primary flex items-center gap-1 group-hover:translate-x-0.5 transition-transform">
                    <span>Open Live Monitor</span>
                    <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </main>
  );
};
