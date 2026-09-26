import React from 'react';
import { NavigationTab } from '../types';

interface SideNavBarProps {
  currentTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  pendingCount: number;
  fleetPaused: boolean;
  onTogglePauseFleet: () => void;
  onOpenDocModal: () => void;
  onOpenSupportModal: () => void;
}

export const SideNavBar: React.FC<SideNavBarProps> = ({
  currentTab,
  onSelectTab,
  pendingCount,
  fleetPaused,
  onTogglePauseFleet,
  onOpenDocModal,
  onOpenSupportModal
}) => {
  return (
    <aside className="sticky top-0 self-start h-screen w-64 flex-shrink-0 flex flex-col justify-between bg-surface-container-lowest border-r border-outline-variant/40 shadow-[0_4px_24px_-2px_rgba(42,42,40,0.04)] z-50 select-none overflow-y-auto">
      <div className="w-64 p-space-md flex flex-col gap-space-md">
        {/* Brand Emblem & Identity */}
        <div 
          onClick={() => onSelectTab('inbox')}
          className="flex items-center gap-3 px-2 py-1 cursor-pointer group"
        >
          <div className="w-8 h-8 rounded-lg bg-surface-container-high flex items-center justify-center text-primary border border-outline-variant/30 group-hover:border-primary/40 transition-colors">
            <span className="material-symbols-outlined text-[20px]">shield</span>
          </div>
          <div>
            <h1 className="text-headline-sm font-headline-sm text-on-surface tracking-tight leading-none">
              AgentGuard
            </h1>
            <p className="text-label-sm font-label-sm text-on-surface-variant/70 mt-0.5">
              Autonomous Oversight
            </p>
          </div>
        </div>

        {/* Action Button: + New Run Initiation */}
        <div className="pt-1">
          <button
            onClick={() => onSelectTab('new-run')}
            className={`w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg font-label-md text-label-md shadow-sm transition-all active:scale-[0.99] ${
              currentTab === 'new-run'
                ? 'bg-primary text-on-primary ring-2 ring-primary/20'
                : 'bg-primary-container text-on-primary-container hover:opacity-95'
            }`}
          >
            <span className="material-symbols-outlined text-[18px]">add</span>
            <span className="font-medium">New Run</span>
          </button>
        </div>

        {/* Navigation Links */}
        <nav className="flex flex-col gap-1 mt-1">
          {/* Inbox */}
          <button
            onClick={() => onSelectTab('inbox')}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg transition-colors text-left ${
              currentTab === 'inbox'
                ? 'bg-surface-container-high text-primary font-medium'
                : 'text-on-surface-variant hover:bg-surface-container-low'
            }`}
          >
            <div className="flex items-center gap-3">
              <span
                className="material-symbols-outlined text-[20px]"
                style={currentTab === 'inbox' ? { fontVariationSettings: "'FILL' 1" } : undefined}
              >
                inbox
              </span>
              <span className="text-body-md font-body-md">Inbox</span>
            </div>
            {pendingCount > 0 ? (
              <span className="text-label-sm font-label-sm bg-primary/10 text-primary px-2 py-0.5 rounded-full border border-primary/20 font-medium">
                {pendingCount} Pending
              </span>
            ) : (
              <span className="text-label-sm font-label-sm text-on-surface-variant/50 px-2 py-0.5">
                0
              </span>
            )}
          </button>

          {/* Active Runs */}
          <button
            onClick={() => onSelectTab('active-runs')}
            className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-colors text-left ${
              currentTab === 'active-runs' || currentTab === 'run-monitor'
                ? 'bg-surface-container-high text-primary font-medium'
                : 'text-on-surface-variant hover:bg-surface-container-low'
            }`}
          >
            <span
              className="material-symbols-outlined text-[20px]"
              style={currentTab === 'active-runs' || currentTab === 'run-monitor' ? { fontVariationSettings: "'FILL' 1" } : undefined}
            >
              play_circle
            </span>
            <span className="text-body-md font-body-md">Active Runs</span>
          </button>

          {/* Policies & Guardrails */}
          <button
            onClick={() => onSelectTab('policies')}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg transition-colors text-left ${
              currentTab === 'policies'
                ? 'bg-surface-container-high text-primary font-medium'
                : 'text-on-surface-variant hover:bg-surface-container-low'
            }`}
          >
            <div className="flex items-center gap-3">
              <span
                className="material-symbols-outlined text-[20px]"
                style={currentTab === 'policies' ? { fontVariationSettings: "'FILL' 1" } : undefined}
              >
                shield
              </span>
              <span className="text-body-md font-body-md">Policies &amp; Guardrails</span>
            </div>
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-outline-variant/30 text-on-surface-variant/60 border border-outline-variant/40 tracking-wide leading-none">
              U
            </span>
          </button>

          {/* Execution Traces */}
          <button
            onClick={() => onSelectTab('traces')}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg transition-colors text-left ${
              currentTab === 'traces'
                ? 'bg-surface-container-high text-primary font-medium'
                : 'text-on-surface-variant hover:bg-surface-container-low'
            }`}
          >
            <div className="flex items-center gap-3">
              <span
                className="material-symbols-outlined text-[20px]"
                style={currentTab === 'traces' ? { fontVariationSettings: "'FILL' 1" } : undefined}
              >
                account_tree
              </span>
              <span className="text-body-md font-body-md">Execution Traces</span>
            </div>
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-outline-variant/30 text-on-surface-variant/60 border border-outline-variant/40 tracking-wide leading-none">
              U
            </span>
          </button>

          {/* Settings */}
          <button
            onClick={() => onSelectTab('settings')}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg transition-colors text-left ${
              currentTab === 'settings'
                ? 'bg-surface-container-high text-primary font-medium'
                : 'text-on-surface-variant hover:bg-surface-container-low'
            }`}
          >
            <div className="flex items-center gap-3">
              <span
                className="material-symbols-outlined text-[20px]"
                style={currentTab === 'settings' ? { fontVariationSettings: "'FILL' 1" } : undefined}
              >
                settings
              </span>
              <span className="text-body-md font-body-md">Settings</span>
            </div>
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-outline-variant/30 text-on-surface-variant/60 border border-outline-variant/40 tracking-wide leading-none">
              U
            </span>
          </button>
        </nav>
      </div>

      {/* SideNav Bottom Cluster */}
      <div className="p-space-md border-t border-outline-variant/30 flex flex-col gap-2 bg-surface-container-lowest">
        {/* Quick Action CTA: Pause / Resume Fleet */}
        <button
          onClick={onTogglePauseFleet}
          className={`w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg border text-label-md font-label-md transition-colors active:scale-[0.99] ${
            fleetPaused
              ? 'bg-[#FBF4E8] text-[#805200] border-[#EACD9B] hover:bg-[#F5EAD4]'
              : 'border-outline-variant/50 text-on-surface-variant hover:bg-surface-container-low hover:text-error'
          }`}
        >
          <span
            className={`material-symbols-outlined text-[16px] ${
              fleetPaused ? 'text-[#805200]' : ''
            }`}
          >
            {fleetPaused ? 'play_arrow' : 'pause_circle'}
          </span>
          <span>{fleetPaused ? 'Resume Fleet' : 'Pause Fleet'}</span>
        </button>

        <div className="flex flex-col gap-0.5 mt-1">
          <button
            onClick={onOpenDocModal}
            className="w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg text-on-surface-variant/80 hover:text-on-surface hover:bg-surface-container-low transition-colors text-body-sm font-body-sm text-left"
          >
            <span className="material-symbols-outlined text-[16px]">menu_book</span>
            <span>Documentation</span>
          </button>
          <button
            onClick={onOpenSupportModal}
            className="w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg text-on-surface-variant/80 hover:text-on-surface hover:bg-surface-container-low transition-colors text-body-sm font-body-sm text-left"
          >
            <span className="material-symbols-outlined text-[16px]">help</span>
            <span>Support</span>
          </button>
        </div>
      </div>
    </aside>
  );
};
