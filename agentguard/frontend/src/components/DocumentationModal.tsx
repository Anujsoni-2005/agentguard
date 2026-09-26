import React from 'react';

interface DocumentationModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const DocumentationModal: React.FC<DocumentationModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4 animate-in fade-in duration-150">
      <div className="bg-surface-container-lowest max-w-2xl w-full rounded-2xl border border-outline-variant/40 shadow-2xl p-6 space-y-5 max-h-[85vh] overflow-y-auto">
        <div className="flex items-center justify-between pb-3 border-b border-surface-container-high">
          <div className="flex items-center gap-2.5">
            <span className="material-symbols-outlined text-primary text-[22px]">menu_book</span>
            <h3 className="text-headline-sm font-headline-sm text-on-surface font-serif">
              AgentGuard Architecture &amp; Oversight Guide
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors cursor-pointer"
          >
            ✕
          </button>
        </div>

        <div className="space-y-4 text-body-sm font-body-sm text-on-surface leading-relaxed">
          <div className="p-4 rounded-xl bg-surface-container-low border border-outline-variant/30 space-y-1.5">
            <div className="font-semibold text-primary">1. Human-in-the-Loop Interlock Gateways</div>
            <p className="text-on-surface-variant">
              When an autonomous agent attempts a high-entropy tool call, an unrecoverable mutation (e.g. <code>fs.remove</code>, <code>cluster.exec_partition_transfer</code>), or encounters semantic uncertainty above 0.42, execution halts into an <code>ASK_HUMAN</code> state.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-surface-container-low border border-outline-variant/30 space-y-1.5">
            <div className="font-semibold text-secondary">2. Deterministic Tripwires &amp; Virtual Scratchpads</div>
            <p className="text-on-surface-variant">
              Policy <code>[SEC-049: FileSystemIsolation]</code> actively trips when agents attempt writing outside declared volume sandboxes. Rather than crashing, the agent is redirected to an ephemeral in-memory ramdisk.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-surface-container-low border border-outline-variant/30 space-y-1.5">
            <div className="font-semibold text-tertiary">3. Step Budgets and Compute Hard Caps</div>
            <p className="text-on-surface-variant">
              Every swarm execution maintains a deterministic step counter (default 50) and token expenditure ceiling (default $10.00). If limits are approached, early warning escalations notify safety engineers.
            </p>
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-surface-container-low border border-outline-variant text-on-surface text-label-md font-label-md hover:bg-surface-container transition-colors cursor-pointer"
          >
            Close Documentation
          </button>
        </div>
      </div>
    </div>
  );
};
