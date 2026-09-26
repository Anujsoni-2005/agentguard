import React from 'react';
import { ApprovalCard } from '../types';

interface ApprovalsInboxProps {
  approvals: ApprovalCard[];
  searchFilter: string;
  onApprove: (id: string) => void;
  onReject: (id: string) => void;
  onInspectTrace: (card: ApprovalCard) => void;
  onResetApprovals: () => void;
}

export const ApprovalsInbox: React.FC<ApprovalsInboxProps> = ({
  approvals,
  searchFilter,
  onApprove,
  onReject,
  onInspectTrace,
  onResetApprovals
}) => {
  const filteredApprovals = approvals.filter((item) => {
    if (item.status !== 'pending') return false;
    if (!searchFilter.trim()) return true;
    const q = searchFilter.toLowerCase();
    return (
      item.agentId.toLowerCase().includes(q) ||
      item.actionType.toLowerCase().includes(q) ||
      item.title.toLowerCase().includes(q) ||
      item.reasoning.toLowerCase().includes(q) ||
      item.codePayload.toLowerCase().includes(q)
    );
  });

  const getActionIcon = (type: ApprovalCard['actionType']) => {
    switch (type) {
      case 'cli.exec':
        return 'terminal';
      case 'cloud.deploy':
        return 'cloud_upload';
      case 'fs.remove':
        return 'delete_sweep';
      case 'webhook.dispatch':
        return 'webhook';
      default:
        return 'code';
    }
  };

  const getActionIconBg = (type: ApprovalCard['actionType']) => {
    switch (type) {
      case 'cli.exec':
        return 'text-primary';
      case 'cloud.deploy':
        return 'text-secondary';
      case 'fs.remove':
        return 'text-primary';
      case 'webhook.dispatch':
        return 'text-primary-container';
      default:
        return 'text-primary';
    }
  };

  return (
    <main className="flex-1 px-margin py-8 max-w-6xl w-full mx-auto">
      {/* Headline & Editorial Intro */}
      <div className="mb-8">
        <div className="flex items-baseline justify-between">
          <h2 className="text-headline-lg font-headline-lg text-on-surface tracking-tight text-3xl font-serif">
            Approvals Inbox
          </h2>
          <span className="text-code-sm font-code-sm text-on-surface-variant/70">
            Sync latency: 28ms
          </span>
        </div>
        <p className="text-body-lg font-body-lg text-on-surface-variant mt-1.5 font-light">
          {filteredApprovals.length} agent{' '}
          {filteredApprovals.length === 1 ? 'intervention' : 'interventions'} awaiting authorization
          across active autonomy pipelines.
        </p>
      </div>

      {/* Feed of Pending Approval Cards */}
      {filteredApprovals.length === 0 ? (
        <div className="bg-surface-container-lowest rounded-xl border border-outline-variant/40 p-12 text-center space-y-4 shadow-[0_2px_12px_-2px_rgba(42,42,40,0.03)]">
          <div className="w-12 h-12 mx-auto rounded-full bg-secondary-container/40 text-secondary flex items-center justify-center">
            <span className="material-symbols-outlined text-[28px]">verified</span>
          </div>
          <div>
            <h3 className="text-headline-sm font-headline-sm text-on-surface font-serif">
              Inbox is Clear
            </h3>
            <p className="text-body-sm font-body-sm text-on-surface-variant mt-1 max-w-md mx-auto">
              No pending intervention gates waiting for sign-off. All agent pipelines are currently
              operating within autonomous policy thresholds.
            </p>
          </div>
          <button
            onClick={onResetApprovals}
            className="px-4 py-2 rounded-lg bg-surface-container-low hover:bg-surface-container border border-outline-variant/40 text-on-surface text-label-md font-label-md transition-colors cursor-pointer"
          >
            Reset Simulation Queue (4 Pending)
          </button>
        </div>
      ) : (
        <div className="flex flex-col gap-6">
          {filteredApprovals.map((card) => {
            const isSage = card.confidence >= 90;
            const isAmber = card.confidence < 90 && card.confidence >= 75;
            const isWarning = card.confidence < 75;

            return (
              <article
                key={card.id}
                className="bg-surface-container-lowest rounded-xl border border-outline-variant/40 shadow-[0_2px_12px_-2px_rgba(42,42,40,0.03)] p-6 transition-all hover:border-outline-variant/70"
              >
                {/* Card Header Info */}
                <div className="flex items-center justify-between pb-4 border-b border-surface-container-high">
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-7 h-7 rounded-md bg-surface-container-high flex items-center justify-center ${getActionIconBg(
                        card.actionType
                      )}`}
                    >
                      <span className="material-symbols-outlined text-[16px]">
                        {getActionIcon(card.actionType)}
                      </span>
                    </div>
                    <span className="text-code-md font-code-md font-medium text-on-surface">
                      {card.agentId}
                    </span>
                    <span className="w-1 h-1 rounded-full bg-outline-variant"></span>
                    <span className="text-label-sm font-label-sm text-on-surface-variant/70">
                      {card.timeAgo}
                    </span>
                    <span className="px-2 py-0.5 rounded text-code-sm font-code-sm bg-surface-container text-on-surface-variant">
                      {card.actionType}
                    </span>
                  </div>

                  {/* Confidence Score Pill */}
                  <div
                    className={`flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-label-sm font-label-sm font-medium ${
                      isSage
                        ? 'bg-secondary-container/40 border-secondary/30 text-secondary'
                        : isAmber
                        ? 'bg-tertiary-fixed/30 border-tertiary-container/30 text-tertiary'
                        : 'bg-tertiary-fixed/40 border-tertiary/30 text-tertiary'
                    }`}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        isSage ? 'bg-secondary' : isAmber ? 'bg-tertiary' : 'bg-[#C98A2C]'
                      }`}
                    ></span>
                    <span>{card.confidence}% Confidence</span>
                  </div>
                </div>

                {/* Description & Reason */}
                <div className="mt-4">
                  <h3 className="text-body-lg font-body-lg font-medium text-on-surface">
                    {card.title}
                  </h3>
                  <p className="text-body-sm font-body-sm text-on-surface-variant mt-1 flex items-center gap-1.5">
                    <span
                      className={`material-symbols-outlined text-[15px] ${
                        card.actionType === 'cloud.deploy' || card.actionType === 'webhook.dispatch'
                          ? 'text-secondary'
                          : 'text-tertiary'
                      }`}
                    >
                      psychology
                    </span>
                    <span>{card.reasoning}</span>
                  </p>
                </div>

                {/* Code / Command Payload */}
                <div className="mt-3.5 rounded-lg bg-surface-container-low border border-outline-variant/30 p-3.5 font-code-sm text-code-sm text-on-surface overflow-x-auto">
                  <div
                    className={`flex items-center justify-between mb-1.5 select-none text-[10px] ${
                      card.isDestructive
                        ? 'text-error/70 font-medium'
                        : 'text-on-surface-variant/50'
                    }`}
                  >
                    <span>{card.codeHeaderLeft}</span>
                    <span>{card.codeHeaderRight}</span>
                  </div>
                  {card.isCodeJson ? (
                    <pre className="leading-relaxed">
                      <code>{card.codePayload}</code>
                    </pre>
                  ) : (
                    <code
                      className={
                        card.isDestructive ? 'text-error/90 font-medium' : 'text-on-surface'
                      }
                    >
                      {card.codePayload}
                    </code>
                  )}
                </div>

                {/* Card Action Area */}
                <div className="mt-5 pt-3 flex items-center justify-between border-t border-surface-container-high/60">
                  <button
                    onClick={() => onInspectTrace(card)}
                    className="text-label-sm font-label-sm text-on-surface-variant/70 hover:text-primary transition-colors flex items-center gap-1 cursor-pointer"
                  >
                    <span className="material-symbols-outlined text-[15px]">visibility</span>
                    <span>Inspect Trace</span>
                  </button>

                  <div className="flex items-center gap-2.5">
                    <button
                      onClick={() => onReject(card.id)}
                      className="px-3.5 py-1.5 rounded-full text-label-md font-label-md text-error bg-error-container/40 border border-error/20 hover:bg-error-container/70 transition-colors active:scale-[0.98] cursor-pointer"
                    >
                      Reject
                    </button>
                    <button
                      onClick={() => onApprove(card.id)}
                      className="px-4 py-1.5 rounded-full text-label-md font-label-md text-secondary bg-secondary-container/40 border border-secondary/30 hover:bg-secondary-container/70 transition-colors active:scale-[0.98] font-medium flex items-center gap-1 cursor-pointer"
                    >
                      <span className="material-symbols-outlined text-[15px]">check</span>
                      <span>Approve</span>
                    </button>
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      )}

      {/* Empty state footer hint */}
      <div className="text-center py-12 text-on-surface-variant/60">
        <p className="text-body-sm font-body-sm">
          All other agent pipelines operating within designated autonomous safety parameters.
        </p>
      </div>
    </main>
  );
};
