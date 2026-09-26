import React from 'react';

interface SupportModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SupportModal: React.FC<SupportModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4 animate-in fade-in duration-150">
      <div className="bg-surface-container-lowest max-w-md w-full rounded-2xl border border-outline-variant/40 shadow-2xl p-6 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-surface-container-high">
          <div className="flex items-center gap-2.5">
            <span className="material-symbols-outlined text-secondary text-[22px]">help</span>
            <h3 className="text-headline-sm font-headline-sm text-on-surface font-serif">
              Lead Oversight Support
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors cursor-pointer"
          >
            ✕
          </button>
        </div>

        <div className="space-y-3 text-body-sm font-body-sm text-on-surface">
          <p className="text-on-surface-variant">
            For critical autonomy incidents, unverified state branches, or cluster security freezes, contact the on-duty AI Safety and Infrastructure Response Team:
          </p>
          <div className="p-3 bg-surface-container-low rounded-lg border border-outline-variant/30 space-y-1 font-code-sm text-code-sm">
            <div>Incident Hotline: <span className="text-primary font-semibold">+1 (800) 555-SAFE</span></div>
            <div>On-Call Pager: <span className="text-secondary font-semibold">safety-oncall@agentguard.internal</span></div>
            <div>Bridge Channel: <span className="text-on-surface font-semibold">#ai-swarm-containment</span></div>
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-surface-container-low border border-outline-variant text-on-surface text-label-md font-label-md hover:bg-surface-container transition-colors cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
};
