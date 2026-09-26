import React from 'react';
import { ActiveRunData } from '../types';

interface ExportLogModalProps {
  isOpen: boolean;
  onClose: () => void;
  run: ActiveRunData;
}

export const ExportLogModal: React.FC<ExportLogModalProps> = ({ isOpen, onClose, run }) => {
  if (!isOpen) return null;

  const jsonString = JSON.stringify(run, null, 2);

  const handleDownload = () => {
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${run.id}-audit-log.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4 animate-in fade-in duration-150">
      <div className="bg-surface-container-lowest max-w-2xl w-full rounded-2xl border border-outline-variant/40 shadow-2xl p-6 space-y-4 max-h-[85vh] flex flex-col">
        <div className="flex items-center justify-between pb-3 border-b border-surface-container-high">
          <div className="flex items-center gap-2.5">
            <span className="material-symbols-outlined text-secondary text-[22px]">download</span>
            <h3 className="text-headline-sm font-headline-sm text-on-surface font-serif">
              Export Audit Run Log ({run.id})
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors cursor-pointer"
          >
            ✕
          </button>
        </div>

        <div className="flex-1 overflow-y-auto bg-surface-container-low p-4 rounded-lg border border-outline-variant/30 font-code-sm text-code-sm text-on-surface">
          <pre>
            <code>{jsonString}</code>
          </pre>
        </div>

        <div className="flex items-center justify-between pt-2">
          <span className="text-code-sm text-on-surface-variant">
            Size: ~{(jsonString.length / 1024).toFixed(1)} KB • SHA256 Armed
          </span>
          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg border border-outline-variant text-on-surface text-label-md font-label-md hover:bg-surface-container transition-colors cursor-pointer"
            >
              Close
            </button>
            <button
              onClick={handleDownload}
              className="px-4 py-2 rounded-lg bg-primary hover:bg-[#833B24] text-on-primary text-label-md font-label-md font-medium transition-colors shadow-sm flex items-center gap-1.5 cursor-pointer"
            >
              <span className="material-symbols-outlined text-[16px]">download</span>
              <span>Download JSON</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
