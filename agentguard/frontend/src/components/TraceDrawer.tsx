import React from 'react';
import { ApprovalCard } from '../types';

interface TraceDrawerProps {
  card: ApprovalCard | null;
  onClose: () => void;
  onGoToRun?: (runId: string) => void;
}

export const TraceDrawer: React.FC<TraceDrawerProps> = ({ card, onClose, onGoToRun }) => {
  if (!card) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/20 backdrop-blur-xs transition-opacity animate-in fade-in duration-200">
      <div className="w-full max-w-xl bg-surface-container-lowest h-full shadow-2xl border-l border-outline-variant/40 flex flex-col justify-between overflow-y-auto">
        <div className="p-6 space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between pb-4 border-b border-surface-container-high">
            <div className="flex items-center gap-2.5">
              <span className="material-symbols-outlined text-primary text-[20px]">
                account_tree
              </span>
              <div>
                <h3 className="text-headline-sm font-headline-sm text-on-surface font-serif">
                  Trace Inspector
                </h3>
                <span className="font-code-sm text-code-sm text-on-surface-variant">
                  {card.traceId || 'trc-default-99a'}
                </span>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-on-surface-variant hover:bg-surface-container-low hover:text-on-surface transition-colors cursor-pointer"
            >
              ✕
            </button>
          </div>

          {/* Metadata Grid */}
          <div className="grid grid-cols-2 gap-3 text-body-sm font-body-sm">
            <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant/30">
              <span className="text-label-sm font-label-sm text-on-surface-variant uppercase">
                Agent Origin
              </span>
              <div className="font-code-sm text-code-sm font-semibold text-on-surface mt-0.5">
                {card.agentId}
              </div>
            </div>
            <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant/30">
              <span className="text-label-sm font-label-sm text-on-surface-variant uppercase">
                Action Type
              </span>
              <div className="font-code-sm text-code-sm font-semibold text-primary mt-0.5">
                {card.actionType}
              </div>
            </div>
            <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant/30">
              <span className="text-label-sm font-label-sm text-on-surface-variant uppercase">
                Confidence
              </span>
              <div className="font-code-sm text-code-sm font-semibold text-secondary mt-0.5">
                {card.confidence}%
              </div>
            </div>
            <div className="bg-surface-container-low p-3 rounded-lg border border-outline-variant/30">
              <span className="text-label-sm font-label-sm text-on-surface-variant uppercase">
                Latency / Age
              </span>
              <div className="font-code-sm text-code-sm text-on-surface mt-0.5">
                {card.timeAgo} (18ms sync)
              </div>
            </div>
          </div>

          {/* Action Context */}
          <div className="space-y-2">
            <div className="text-label-md font-label-md font-semibold text-on-surface">
              Task Intent
            </div>
            <p className="text-body-md font-body-md text-on-surface leading-relaxed">
              {card.title}
            </p>
          </div>

          {/* Agent Reasoning */}
          <div className="space-y-2">
            <div className="text-label-md font-label-md font-semibold text-on-surface flex items-center gap-1.5">
              <span className="material-symbols-outlined text-[16px] text-tertiary">
                psychology
              </span>
              <span>Deliberate Chain of Thought</span>
            </div>
            <div className="p-3.5 rounded-lg bg-surface-container-low border border-outline-variant/30 text-body-sm font-body-sm italic text-on-surface-variant leading-relaxed">
              “{card.reasoning} Safety interlock policy [DATA-004] triggered pause to protect integrity before executing mutation.”
            </div>
          </div>

          {/* Raw Payload Inspection */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-label-md font-label-md font-semibold text-on-surface">
              <span>Execution Payload</span>
              <span className="text-label-sm font-label-sm font-normal text-on-surface-variant">
                {card.codeHeaderLeft}
              </span>
            </div>
            <div className="bg-surface-container-low border border-outline-variant/30 rounded-lg p-3 font-code-sm text-code-sm text-on-surface overflow-x-auto">
              {card.isCodeJson ? (
                <pre>
                  <code>{card.codePayload}</code>
                </pre>
              ) : (
                <code>{card.codePayload}</code>
              )}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="p-6 border-t border-surface-container-high bg-surface-container-low/50 flex items-center justify-between">
          {card.runId && onGoToRun && (
            <button
              onClick={() => {
                onGoToRun(card.runId!);
                onClose();
              }}
              className="text-label-md font-label-md text-primary hover:underline flex items-center gap-1 cursor-pointer"
            >
              <span>Jump to Active Run Monitor</span>
              <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
            </button>
          )}
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-surface-container-lowest border border-outline-variant text-on-surface text-label-md font-label-md hover:bg-surface-container transition-colors ml-auto cursor-pointer"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
