import React from 'react';

interface NotificationsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const NotificationsModal: React.FC<NotificationsModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4 animate-in fade-in duration-150">
      <div className="bg-surface-container-lowest max-w-lg w-full rounded-2xl border border-outline-variant/40 shadow-2xl p-6 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-surface-container-high">
          <div className="flex items-center gap-2.5">
            <span className="material-symbols-outlined text-primary text-[22px]">notifications</span>
            <h3 className="text-headline-sm font-headline-sm text-on-surface font-serif">
              Oversight Event Notifications
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors cursor-pointer"
          >
            ✕
          </button>
        </div>

        <div className="space-y-2.5 max-h-80 overflow-y-auto">
          <div className="p-3 rounded-lg bg-surface-container-low border border-outline-variant/30 flex gap-3 text-body-sm">
            <span className="material-symbols-outlined text-[#C98A2C] text-[18px] shrink-0 mt-0.5">
              pan_tool
            </span>
            <div>
              <div className="font-semibold text-on-surface">Intervention Triggered</div>
              <div className="text-on-surface-variant text-body-sm">
                Step 18 in <code>run-8492-synthetics</code> blocked on destination cluster shard overwrite check.
              </div>
              <div className="text-[11px] text-on-surface-variant/70 mt-1">2 mins ago</div>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-surface-container-low border border-outline-variant/30 flex gap-3 text-body-sm">
            <span className="material-symbols-outlined text-error text-[18px] shrink-0 mt-0.5">
              shield_lock
            </span>
            <div>
              <div className="font-semibold text-on-surface">Tripwire Activated [SEC-049]</div>
              <div className="text-on-surface-variant text-body-sm">
                Intercepted unauthorized write to <code>/etc/hosts</code> by agent-synthetics-402. Ephemeral recovery succeeded.
              </div>
              <div className="text-[11px] text-on-surface-variant/70 mt-1">11 mins ago</div>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-surface-container-low border border-outline-variant/30 flex gap-3 text-body-sm">
            <span className="material-symbols-outlined text-secondary text-[18px] shrink-0 mt-0.5">
              check_circle
            </span>
            <div>
              <div className="font-semibold text-on-surface">Parity Verified</div>
              <div className="text-on-surface-variant text-body-sm">
                Benchmark evaluation suite <code>run-8482-eval</code> completed with zero regressions.
              </div>
              <div className="text-[11px] text-on-surface-variant/70 mt-1">1 hour ago</div>
            </div>
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-surface-container-low border border-outline-variant text-on-surface text-label-md font-label-md hover:bg-surface-container transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
