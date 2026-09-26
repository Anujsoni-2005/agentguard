import React from 'react';

interface EmergencyHaltModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirmHalt: () => void;
  fleetCount: number;
}

export const EmergencyHaltModal: React.FC<EmergencyHaltModalProps> = ({
  isOpen,
  onClose,
  onConfirmHalt,
  fleetCount
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4 animate-in fade-in duration-150">
      <div className="bg-surface-container-lowest max-w-lg w-full rounded-2xl border border-error/40 shadow-2xl p-6 space-y-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-[#F9EBE9] text-[#B34A3E] flex items-center justify-center shrink-0">
            <span className="material-symbols-outlined text-[24px]">front_hand</span>
          </div>
          <div>
            <h3 className="text-headline-sm font-headline-sm text-on-surface font-serif">
              Emergency Fleet Halt
            </h3>
            <p className="text-body-sm font-body-sm text-on-surface-variant">
              Immediate hard stop across all active agent autonomy pipelines.
            </p>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#F9EBE9]/50 border border-error/20 text-body-sm font-body-sm text-on-surface space-y-2">
          <div className="font-semibold text-[#B34A3E] flex items-center gap-1.5">
            <span className="material-symbols-outlined text-[16px]">warning</span>
            <span>Immediate Kill-Switch Interlock</span>
          </div>
          <p className="text-on-surface-variant leading-relaxed">
            Triggering an emergency halt immediately revokes active IAM delegation nonces, pauses all{' '}
            <strong className="text-on-surface font-medium">{fleetCount} active swarm agents</strong>, and blocks queued tool executions until an operator manually performs safety verification.
          </p>
        </div>

        <div className="flex items-center justify-end gap-3 pt-2">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg border border-outline-variant text-on-surface text-label-md font-label-md hover:bg-surface-container transition-colors cursor-pointer"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              onConfirmHalt();
              onClose();
            }}
            className="px-5 py-2 rounded-lg bg-error hover:bg-[#8f1313] text-on-error text-label-md font-label-md font-medium transition-colors shadow-sm flex items-center gap-1.5 cursor-pointer"
          >
            <span className="material-symbols-outlined text-[18px]">front_hand</span>
            <span>Confirm Emergency Halt</span>
          </button>
        </div>
      </div>
    </div>
  );
};
