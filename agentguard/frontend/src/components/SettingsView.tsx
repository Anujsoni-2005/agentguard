import React, { useState } from 'react';

export const SettingsView: React.FC = () => {
  const [slackWebhook, setSlackWebhook] = useState('https://hooks.slack.com/services/T00/B00/XXXX');
  const [latencyThreshold, setLatencyThreshold] = useState('1200');
  const [entropyCeiling, setEntropyCeiling] = useState('0.42');
  const [autoApproveSafe, setAutoApproveSafe] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <main className="flex-1 px-margin py-8 max-w-4xl w-full mx-auto space-y-6">
      {/* Upcoming notice */}
      <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-surface-container border border-outline-variant/50">
        <span className="text-[10px] font-bold px-2 py-1 rounded bg-outline-variant/30 text-on-surface-variant border border-outline-variant/50 tracking-widest shrink-0">U UPCOMING</span>
        <p className="text-body-sm font-body-sm text-on-surface-variant">
          Settings &mdash; UI preview only. No backend <code className="font-code-sm text-code-sm">PATCH /v1/settings</code> endpoint exists yet. Changes are not persisted.
        </p>
      </div>
      <div>
        <h2 className="text-headline-lg font-headline-lg text-on-surface tracking-tight text-3xl font-serif">
          Runtime Oversight Settings
        </h2>
        <p className="text-body-lg font-body-lg text-on-surface-variant mt-1.5 font-light">
          Configure enterprise notification webhooks, safety thresholds, and autonomous bounds.
        </p>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Section 1: Notification Webhook */}
        <div className="bg-surface-container-lowest rounded-xl border border-outline-variant/40 p-6 space-y-4 shadow-[0_2px_12px_-2px_rgba(42,42,40,0.03)]">
          <h3 className="text-headline-sm font-headline-sm text-on-surface font-serif">
            Escalation Dispatch Integrations
          </h3>
          <div className="space-y-2">
            <label className="text-label-md font-label-md text-on-surface font-medium block">
              Slack Emergency Webhook URL
            </label>
            <input
              type="text"
              value={slackWebhook}
              onChange={(e) => setSlackWebhook(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border border-outline-variant/60 bg-surface-container-lowest font-code-sm text-code-sm text-on-surface focus:outline-none focus:border-primary"
            />
            <p className="text-body-sm font-body-sm text-on-surface-variant">
              AgentGuard dispatches <code>ASK_HUMAN</code> escalations and tripwire violations to this channel.
            </p>
          </div>
        </div>

        {/* Section 2: Safety Thresholds */}
        <div className="bg-surface-container-lowest rounded-xl border border-outline-variant/40 p-6 space-y-4 shadow-[0_2px_12px_-2px_rgba(42,42,40,0.03)]">
          <h3 className="text-headline-sm font-headline-sm text-on-surface font-serif">
            Autonomous Safety Thresholds
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-label-md font-label-md text-on-surface font-medium block">
                Latency Warning Ceiling (ms)
              </label>
              <input
                type="number"
                value={latencyThreshold}
                onChange={(e) => setLatencyThreshold(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-outline-variant/60 bg-surface-container-lowest font-code-md text-code-md text-on-surface focus:outline-none focus:border-primary"
              />
              <span className="text-label-sm text-on-surface-variant">
                Default: 1200ms per step
              </span>
            </div>

            <div className="space-y-1.5">
              <label className="text-label-md font-label-md text-on-surface font-medium block">
                Semantic Entropy Ceiling
              </label>
              <input
                type="text"
                value={entropyCeiling}
                onChange={(e) => setEntropyCeiling(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-outline-variant/60 bg-surface-container-lowest font-code-md text-code-md text-on-surface focus:outline-none focus:border-primary"
              />
              <span className="text-label-sm text-on-surface-variant">
                Hard stop if token uncertainty exceeds score
              </span>
            </div>
          </div>

          <div className="pt-2 flex items-center justify-between border-t border-outline-variant/20">
            <div>
              <div className="text-label-md font-label-md font-medium text-on-surface">
                Auto-Approve Read-Only Operations with &gt;95% Confidence
              </div>
              <div className="text-body-sm font-body-sm text-on-surface-variant">
                Bypass human verification for idempotent read telemetry.
              </div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={autoApproveSafe}
                onChange={(e) => setAutoApproveSafe(e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-surface-container-highest peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-outline-variant after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-secondary"></div>
            </label>
          </div>
        </div>

        {/* Save button */}
        <div className="flex items-center justify-between">
          {saved && (
            <span className="text-label-md font-label-md text-secondary flex items-center gap-1.5">
              <span className="material-symbols-outlined text-[18px]">check_circle</span>
              <span>Settings successfully persisted to runtime control cluster.</span>
            </span>
          )}
          <button
            type="submit"
            className="ml-auto px-6 py-2.5 rounded-lg bg-primary hover:bg-[#833B24] text-on-primary text-label-md font-label-md font-medium transition-colors shadow-sm cursor-pointer"
          >
            Save Configuration
          </button>
        </div>
      </form>
    </main>
  );
};
