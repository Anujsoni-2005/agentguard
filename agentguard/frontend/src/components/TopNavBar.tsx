import React from 'react';
import { NavigationTab } from '../types';

interface TopNavBarProps {
  currentTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  searchFilter: string;
  onSearchChange: (value: string) => void;
  activeRunId: string;
  fleetCount: number;
  fleetPaused: boolean;
  onReviewAll: () => void;
  onEmergencyHalt: () => void;
  onExportRunLog?: () => void;
  onOpenNotifications: () => void;
  onOpenTuneModal: () => void;
  onOpenUserProfile: () => void;
}

export const TopNavBar: React.FC<TopNavBarProps> = ({
  currentTab,
  onSelectTab,
  searchFilter,
  onSearchChange,
  activeRunId,
  fleetCount,
  fleetPaused,
  onReviewAll,
  onEmergencyHalt,
  onExportRunLog,
  onOpenNotifications,
  onOpenTuneModal,
  onOpenUserProfile
}) => {
  const profileAvatarUrl = "https://lh3.googleusercontent.com/aida-public/AB6AXuBd9-5QJlVoIhLZonIbyiRbThHgGJJD2y-FUXa_y4LgKXplbIkV6Ap7vfC6MexdhUA3o5WDwBpjE1a4jX9ssFX6mJYKJdE0BdodEtt47XMwHD48KP8YsQi_hj8gMd3gAJb4k2HmFFa9lazJdOMmnljLYt0p08Bjp9_6Y9BSca1j8sNpTQ1xy_enKKvr-IgT01INNCnlqGAHszXkfAK1791dwbMiYLPdT8hKaeqdFhR7yrfxlsrYTotxTg";

  if (currentTab === 'inbox') {
    return (
      <header className="h-14 px-margin sticky top-0 z-40 bg-surface-bright/90 backdrop-blur border-b border-outline-variant/40 shadow-[0_2px_12px_-2px_rgba(42,42,40,0.03)] flex items-center justify-between">
        {/* Search & Status Inset */}
        <div className="flex items-center gap-6">
          <div className="relative w-72">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant/60 text-[18px]">
              search
            </span>
            <input
              type="text"
              value={searchFilter}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Filter agent ID, action or tag..."
              className="w-full pl-9 pr-3 py-1.5 bg-surface-container-lowest border border-outline-variant/50 rounded-lg text-body-sm font-body-sm placeholder:text-on-surface-variant/40 focus:outline-none focus:border-primary focus:ring-2 focus:ring-primary/10 transition-all font-body-sm"
            />
            {searchFilter && (
              <button
                onClick={() => onSearchChange('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-on-surface-variant/60 hover:text-on-surface text-[14px]"
              >
                ✕
              </button>
            )}
          </div>

          <div
            className={`flex items-center gap-2 px-2.5 py-1 rounded-full border ${
              fleetPaused
                ? 'bg-[#FBF4E8] border-[#EACD9B] text-[#805200]'
                : 'bg-secondary-container/30 border-secondary/20 text-secondary'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                fleetPaused ? 'bg-[#C98A2C]' : 'bg-secondary animate-pulse'
              }`}
            />
            <span className="text-label-sm font-label-sm font-medium">
              {fleetPaused ? 'Fleet: Paused' : `Fleet: ${fleetCount} Active Agents`}
            </span>
          </div>
        </div>

        {/* Action Cluster */}
        <div className="flex items-center gap-3">
          <button
            onClick={onReviewAll}
            className="px-3 py-1.5 rounded-lg border border-outline-variant/60 bg-surface-container-lowest text-on-surface hover:bg-surface-container-low text-label-md font-label-md transition-colors active:scale-[0.99] cursor-pointer"
          >
            Review All
          </button>
          <button
            onClick={onEmergencyHalt}
            className="px-3 py-1.5 rounded-lg bg-surface-container-lowest border border-error/30 text-error hover:bg-error-container/40 text-label-md font-label-md transition-colors active:scale-[0.99] flex items-center gap-1.5 cursor-pointer"
          >
            <span className="material-symbols-outlined text-[16px]">front_hand</span>
            Emergency Halt
          </button>
          <div className="h-4 w-px bg-outline-variant/50 mx-1"></div>
          <div className="relative group">
            <button
              onClick={onOpenNotifications}
              className="p-1.5 rounded-lg text-on-surface-variant hover:bg-surface-container-low hover:text-on-surface transition-colors cursor-pointer relative"
              title="Notifications (Upcoming)"
            >
              <span className="material-symbols-outlined text-[20px]">notifications</span>
              <span className="absolute -top-1 -right-1 text-[8px] font-bold px-1 py-px rounded bg-outline-variant/40 text-on-surface-variant/50 border border-outline-variant/50 leading-none">U</span>
            </button>
            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-[#1b1c1a] text-[#fcf9f5] text-[11px] rounded-lg shadow-lg whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
              Upcoming — live notification feed not yet implemented
            </div>
          </div>
          <button
            onClick={onOpenTuneModal}
            className="p-1.5 rounded-lg text-on-surface-variant hover:bg-surface-container-low hover:text-on-surface transition-colors cursor-pointer"
            title="Tune Parameters"
          >
            <span className="material-symbols-outlined text-[20px]">tune</span>
          </button>
          <div
            onClick={onOpenUserProfile}
            className="w-8 h-8 rounded-full border border-outline-variant/60 bg-surface-container-high overflow-hidden ml-1 cursor-pointer hover:ring-2 hover:ring-primary/20 transition-all"
            title="Lead AI Safety Engineer"
          >
            <img
              src={profileAvatarUrl}
              alt="Lead AI safety engineer"
              className="w-full h-full object-cover"
            />
          </div>
        </div>
      </header>
    );
  }

  if (currentTab === 'run-monitor') {
    return (
      <header className="h-14 w-full sticky top-0 z-40 bg-surface-bright/95 backdrop-blur border-b border-outline-variant/40 flex items-center justify-between px-space-xl">
        {/* Breadcrumb Navigation */}
        <div className="flex items-center gap-2 text-label-sm font-label-sm">
          <button
            onClick={() => onSelectTab('active-runs')}
            className="text-on-surface-variant hover:text-on-surface transition-colors flex items-center gap-1 cursor-pointer"
          >
            <span className="material-symbols-outlined text-[16px]">arrow_back</span>
            <span>Active Runs</span>
          </button>
          <span className="text-outline-variant">/</span>
          <span className="font-code-sm text-code-sm text-on-surface-variant bg-surface-container px-1.5 py-0.5 rounded border border-outline-variant/40">
            {activeRunId}
          </span>
          <span className="text-outline-variant">/</span>
          <span className="text-on-surface font-medium">Live Monitor</span>
        </div>

        {/* Top Trailing Actions */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-label-sm font-label-sm text-secondary mr-2">
            <span className="w-2 h-2 rounded-full bg-secondary"></span>
            <span>Sync Status: Live Gateway</span>
          </div>
          <div className="relative group">
            <button
              onClick={onExportRunLog}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-outline-variant/60 bg-surface-container-lowest hover:bg-surface-container-low text-on-surface-variant text-label-sm font-label-sm transition-colors shadow-sm cursor-pointer"
            >
              <span className="material-symbols-outlined text-[15px]">download</span>
              <span>Export Run Log</span>
              <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-outline-variant/30 text-on-surface-variant/50 border border-outline-variant/40 tracking-wide leading-none">U</span>
            </button>
            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-[#1b1c1a] text-[#fcf9f5] text-[11px] rounded-lg shadow-lg whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
              Upcoming — export endpoint not yet implemented
            </div>
          </div>
          <button
            onClick={onEmergencyHalt}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-error/30 bg-[#F9EBE9] hover:bg-[#F2DFDD] text-[#B34A3E] text-label-sm font-label-sm font-medium transition-colors shadow-sm cursor-pointer"
          >
            <span className="material-symbols-outlined text-[15px]">report</span>
            <span>Halt Agent</span>
          </button>
          <div className="h-4 w-px bg-outline-variant/50 mx-1"></div>
          <div className="relative group">
            <button
              onClick={onOpenNotifications}
              className="w-8 h-8 rounded-full flex items-center justify-center text-on-surface-variant hover:bg-surface-container transition-colors cursor-pointer relative"
            >
              <span className="material-symbols-outlined text-[18px]">notifications</span>
              <span className="absolute -top-1 -right-1 text-[8px] font-bold px-1 py-px rounded bg-outline-variant/40 text-on-surface-variant/50 border border-outline-variant/50 leading-none">U</span>
            </button>
            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-[#1b1c1a] text-[#fcf9f5] text-[11px] rounded-lg shadow-lg whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
              Upcoming — live notification feed not yet implemented
            </div>
          </div>
          <div
            onClick={onOpenUserProfile}
            className="w-7 h-7 rounded-full bg-primary-fixed border border-primary/20 flex items-center justify-center text-on-primary-fixed text-label-sm font-label-sm font-medium cursor-pointer"
          >
            SE
          </div>
        </div>
      </header>
    );
  }

  if (currentTab === 'new-run') {
    return (
      <header className="flex justify-between items-center h-14 px-margin w-full sticky top-0 z-40 bg-surface-bright/90 backdrop-blur shadow-[0_2px_12px_-2px_rgba(42,42,40,0.03)] border-b border-outline-variant/40">
        {/* Left: Breadcrumb / Path */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-body-sm font-body-sm text-on-surface-variant">
            <button
              onClick={() => onSelectTab('active-runs')}
              className="hover:text-on-surface transition-colors cursor-pointer"
            >
              Active Runs
            </button>
            <span className="text-outline/40">/</span>
            <span className="text-on-surface font-medium">Initialize New Run</span>
          </div>
          <div className="h-3.5 w-px bg-outline-variant/40 mx-1"></div>
          {/* Sync Status Badge */}
          <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-surface-container text-secondary text-label-sm font-label-sm border border-outline-variant/30">
            <span className="w-1.5 h-1.5 rounded-full bg-secondary"></span>
            <span>Sync Status: Live Gateway</span>
          </div>
        </div>

        {/* Right: Contextual Controls & Actions */}
        <div className="flex items-center gap-3">
          <button
            onClick={onOpenTuneModal}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-label-sm font-label-sm text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors cursor-pointer"
          >
            <span className="material-symbols-outlined text-[16px]">drafts</span>
            <span>Drafts (2)</span>
          </button>
          <button
            onClick={onOpenTuneModal}
            className="p-1.5 text-on-surface-variant hover:text-on-surface rounded-lg hover:bg-surface-container transition-colors cursor-pointer"
            title="Filter Traces"
          >
            <span className="material-symbols-outlined text-[18px]">tune</span>
          </button>
          <button
            onClick={onOpenNotifications}
            className="p-1.5 text-on-surface-variant hover:text-on-surface rounded-lg hover:bg-surface-container transition-colors cursor-pointer"
            title="Notifications"
          >
            <span className="material-symbols-outlined text-[18px]">notifications</span>
          </button>
          <div className="h-4 w-px bg-outline-variant/40 mx-1"></div>
          <div className="flex items-center gap-2">
            <button
              onClick={onEmergencyHalt}
              className="px-2.5 py-1 rounded-md text-label-sm font-label-sm text-error bg-error-container/40 border border-error/20 hover:bg-error-container hover:text-on-error-container transition-all cursor-pointer"
            >
              Emergency Halt
            </button>
            <div
              onClick={onOpenUserProfile}
              className="w-7 h-7 rounded-full bg-primary-fixed flex items-center justify-center text-on-primary-fixed text-label-sm font-label-sm font-medium border border-primary/20 cursor-pointer"
            >
              AL
            </div>
          </div>
        </div>
      </header>
    );
  }

  // Fallback for policies, traces, settings
  return (
    <header className="h-14 px-margin sticky top-0 z-40 bg-surface-bright/90 backdrop-blur border-b border-outline-variant/40 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <span className="text-body-sm font-body-sm text-on-surface font-medium capitalize">
          {currentTab.replace('-', ' ')}
        </span>
        <div className="h-3.5 w-px bg-outline-variant/40 mx-1"></div>
        <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-surface-container text-secondary text-label-sm font-label-sm border border-outline-variant/30">
          <span className="w-1.5 h-1.5 rounded-full bg-secondary"></span>
          <span>Live Gateway</span>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={onEmergencyHalt}
          className="px-3 py-1.5 rounded-lg bg-surface-container-lowest border border-error/30 text-error hover:bg-error-container/40 text-label-md font-label-md transition-colors cursor-pointer"
        >
          Emergency Halt
        </button>
        <button
          onClick={onOpenNotifications}
          className="p-1.5 rounded-lg text-on-surface-variant hover:bg-surface-container transition-colors cursor-pointer"
        >
          <span className="material-symbols-outlined text-[20px]">notifications</span>
        </button>
        <div
          onClick={onOpenUserProfile}
          className="w-8 h-8 rounded-full border border-outline-variant/60 bg-surface-container-high overflow-hidden cursor-pointer"
        >
          <img src={profileAvatarUrl} alt="User" className="w-full h-full object-cover" />
        </div>
      </div>
    </header>
  );
};
