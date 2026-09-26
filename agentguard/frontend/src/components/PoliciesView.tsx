import React, { useState } from 'react';
import { PolicyRule } from '../types';
import { POLICIES_LIST } from '../data/mockData';

export const PoliciesView: React.FC = () => {
  const [policies, setPolicies] = useState<PolicyRule[]>(POLICIES_LIST);
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [activeTab, setActiveTab] = useState<'rules' | 'tripwire-log' | 'audit'>('rules');

  const categories = ['All', 'Security', 'Filesystem', 'Network', 'Compute'];

  const filtered = policies.filter((p) => {
    if (selectedCategory === 'All') return true;
    return p.category === selectedCategory;
  });

  const togglePolicyStatus = (id: string) => {
    setPolicies((prev) =>
      prev.map((p) => {
        if (p.id !== id) return p;
        const nextStatus =
          p.status === 'Enforced'
            ? 'Supervisory'
            : p.status === 'Supervisory'
            ? 'Audit-Only'
            : 'Enforced';
        return { ...p, status: nextStatus };
      })
    );
  };

  return (
    <main className="flex-1 px-margin py-8 max-w-6xl w-full mx-auto space-y-6">
      {/* Upcoming notice */}
      <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-surface-container border border-outline-variant/50">
        <span className="text-[10px] font-bold px-2 py-1 rounded bg-outline-variant/30 text-on-surface-variant border border-outline-variant/50 tracking-widest shrink-0">U UPCOMING</span>
        <p className="text-body-sm font-body-sm text-on-surface-variant">
          Policies &amp; Guardrails — UI preview only. The <code className="font-code-sm text-code-sm">/v1/policy</code> backend endpoint is not yet implemented. Rule toggles are local only.
        </p>
      </div>
      <div className="flex flex-col md:flex-row md:items-baseline justify-between gap-4">
        <div>
          <h2 className="text-headline-lg font-headline-lg text-on-surface tracking-tight text-3xl font-serif">
            Policies &amp; Guardrails
          </h2>
          <p className="text-body-lg font-body-lg text-on-surface-variant mt-1.5 font-light">
            Deterministic runtime tripwires, permission boundaries, and supervisory escalations.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-label-sm font-label-sm text-secondary bg-secondary-container/40 border border-secondary/30 px-3 py-1 rounded-full font-medium flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-secondary"></span>
            <span>Policy Tier: STRICT-V2 (Active)</span>
          </span>
        </div>
      </div>

      {/* Category Pills */}
      <div className="flex items-center gap-2 border-b border-outline-variant/30 pb-3">
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-3 py-1 rounded-full text-label-md font-label-md transition-colors cursor-pointer ${
              selectedCategory === cat
                ? 'bg-primary text-on-primary font-medium'
                : 'bg-surface-container text-on-surface-variant hover:bg-surface-container-high'
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Policies Table / Cards */}
      <div className="grid grid-cols-1 gap-4">
        {filtered.map((policy) => {
          const isEnforced = policy.status === 'Enforced';
          return (
            <div
              key={policy.id}
              className="bg-surface-container-lowest rounded-xl border border-outline-variant/40 p-6 shadow-[0_2px_12px_-2px_rgba(42,42,40,0.03)] space-y-3"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 pb-3 border-b border-surface-container-high">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-surface-container-high text-primary flex items-center justify-center">
                    <span className="material-symbols-outlined text-[18px]">
                      {policy.category === 'Filesystem'
                        ? 'folder_supervised'
                        : policy.category === 'Network'
                        ? 'lan'
                        : policy.category === 'Security'
                        ? 'shield_lock'
                        : 'toll'}
                    </span>
                  </div>
                  <div>
                    <span className="font-code-sm text-code-sm text-primary font-medium">
                      {policy.code}
                    </span>
                    <h3 className="text-body-lg font-body-lg font-semibold text-on-surface">
                      {policy.name}
                    </h3>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <button
                    onClick={() => togglePolicyStatus(policy.id)}
                    className={`px-2.5 py-1 rounded-full text-label-sm font-label-sm font-medium border cursor-pointer ${
                      isEnforced
                        ? 'bg-secondary-container/40 border-secondary/30 text-secondary'
                        : policy.status === 'Supervisory'
                        ? 'bg-tertiary-fixed/30 border-tertiary/30 text-tertiary'
                        : 'bg-surface-container border-outline-variant/40 text-on-surface-variant'
                    }`}
                  >
                    ● {policy.status}
                  </button>
                </div>
              </div>

              <p className="text-body-md font-body-md text-on-surface-variant leading-relaxed">
                {policy.description}
              </p>

              <div className="pt-2 flex flex-wrap items-center justify-between gap-3 text-label-sm font-label-sm text-on-surface-variant/70 border-t border-outline-variant/20">
                <div className="flex items-center gap-4">
                  <span>Category: {policy.category}</span>
                  <span>•</span>
                  <span>Trip Invocations: {policy.tripsCount}</span>
                  {policy.lastTripped && (
                    <>
                      <span>•</span>
                      <span className="text-[#805200]">Last Tripped: {policy.lastTripped}</span>
                    </>
                  )}
                </div>
                <span className="text-primary hover:underline cursor-pointer">
                  Configure Rule &rarr;
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </main>
  );
};
