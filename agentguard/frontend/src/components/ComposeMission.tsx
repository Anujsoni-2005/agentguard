import React, { useState, useEffect } from 'react';
import { TEMPLATE_PROMPTS } from '../data/mockData';
import { ActiveRunData } from '../types';

interface ComposeMissionProps {
  onLaunchRun: (newRun: Partial<ActiveRunData>) => void;
  onSimulateDryRun: () => void;
  onSaveTemplate: () => void;
}

export const ComposeMission: React.FC<ComposeMissionProps> = ({
  onLaunchRun,
  onSimulateDryRun,
  onSaveTemplate
}) => {
  const [objective, setObjective] = useState(
    'Conduct recursive security audit on staging cluster us-west-2, synthesize dependency CVE vulnerabilities, and prepare non-destructive remediation patch branches for human review.'
  );
  const [humanInLoop, setHumanInLoop] = useState(true);
  const [stepBudget, setStepBudget] = useState(50);
  const [computeCap, setComputeCap] = useState('10.00');
  const [selectedModel, setSelectedModel] = useState('Claude 3.5 Sonnet (claude-3-5-sonnet-20241022)');
  const [targetEnv, setTargetEnv] = useState('staging-vpc-alpha (Sandboxed, Read/Branch Write)');

  // Calculate live word count & approx tokens
  const words = objective.trim() ? objective.trim().split(/\s+/).length : 0;
  const approxTokens = Math.round(words * 1.55);

  const handleApplyTemplate = (tplKey: keyof typeof TEMPLATE_PROMPTS) => {
    setObjective(TEMPLATE_PROMPTS[tplKey]);
  };

  const handleSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!objective.trim()) return;

    onLaunchRun({
      objective: `“${objective.trim()}”`,
      objectiveDescription: `Deployed in ${targetEnv.split(' ')[0]} with human-in-the-loop ${
        humanInLoop ? 'active' : 'autonomous'
      } and $${computeCap} compute cap.`,
      status: 'RUNNING',
      model: selectedModel.split(' ')[0].toLowerCase(),
      maxSteps: stepBudget,
      computeCap: parseFloat(computeCap) || 10.0,
      environment: targetEnv.split(' ')[0]
    });
  };

  // Keyboard shortcut listener (Cmd+Enter or Ctrl+Enter)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        handleSubmit();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [objective, humanInLoop, stepBudget, computeCap, selectedModel, targetEnv]);

  return (
    <main className="min-h-[calc(100vh-3.5rem)] flex justify-center pb-24 bg-background">
      <div className="w-full max-w-[780px] px-space-md pt-12">
        {/* Header Section: Subtitle kicker & Title */}
        <header className="mb-10 text-left">
          <div className="flex items-center gap-2 mb-2">
            <span className="w-1.5 h-1.5 rounded-full bg-primary"></span>
            <span className="text-label-sm font-label-sm uppercase tracking-widest text-primary font-semibold">
              Session Initialization
            </span>
            <span className="text-outline-variant/60">·</span>
            <span className="text-code-sm font-code-sm text-on-surface-variant">
              ENV: {targetEnv.split(' ')[0]}
            </span>
          </div>
          <h1 className="text-headline-lg font-headline-lg text-on-surface tracking-tight text-3xl font-serif">
            Compose Autonomous Mission
          </h1>
          <p className="mt-2 text-headline-sm font-headline-sm text-on-surface-variant font-light text-base leading-relaxed font-serif">
            Articulate the overarching objective, scope parameters, and runtime guardrails before delegating execution to the autonomous swarm.
          </p>
        </header>

        {/* Form Container */}
        <form className="flex flex-col gap-8" onSubmit={handleSubmit}>
          {/* 1. Agent Objective Hero Canvas */}
          <section className="group relative rounded-xl border border-outline-variant/50 bg-surface-container-lowest p-6 shadow-[0_4px_24px_-2px_rgba(42,42,40,0.04)] focus-within:border-primary-container focus-within:shadow-[0_0_0_3px_rgba(179,92,65,0.08)] transition-all duration-200">
            <div className="flex items-center justify-between pb-3 mb-2 border-b border-surface-container-high">
              <label
                htmlFor="missionObjective"
                className="text-label-md font-label-md text-on-surface-variant font-medium flex items-center gap-2"
              >
                <span className="material-symbols-outlined text-base text-primary">terminal</span>
                <span>Primary Objective &amp; Bounds</span>
              </label>
              <span className="text-code-sm font-code-sm text-on-surface-variant/70">
                Markdown Supported
              </span>
            </div>

            {/* Hero Textarea */}
            <textarea
              id="missionObjective"
              rows={5}
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              placeholder="e.g., Conduct recursive security audit on staging cluster us-west-2, synthesize dependency CVE vulnerabilities, and prepare non-destructive remediation patch branches for human review."
              className="w-full resize-none border-0 bg-transparent p-0 text-headline-md font-headline-md text-on-surface placeholder:text-surface-variant focus:ring-0 leading-relaxed font-normal font-serif focus:outline-none"
            />

            {/* Prompt Footer: Stats & Template Chips */}
            <div className="mt-4 pt-3 flex flex-wrap items-center justify-between gap-3 border-t border-outline-variant/30">
              {/* Template Quick Pill Selectors */}
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-label-sm font-label-sm text-on-surface-variant mr-1">
                  Templates:
                </span>
                {(Object.keys(TEMPLATE_PROMPTS) as Array<keyof typeof TEMPLATE_PROMPTS>).map(
                  (tpl) => (
                    <button
                      key={tpl}
                      type="button"
                      onClick={() => handleApplyTemplate(tpl)}
                      className="px-2 py-0.5 rounded-full bg-surface-container-low hover:bg-surface-container text-body-sm font-body-sm text-on-surface-variant hover:text-on-surface border border-outline-variant/30 transition-colors cursor-pointer"
                    >
                      {tpl}
                    </button>
                  )
                )}
              </div>

              {/* Word & Token Metrics */}
              <div className="text-code-sm font-code-sm text-on-surface-variant flex items-center gap-2">
                <span className="inline-block w-2 h-2 rounded-full bg-secondary"></span>
                <span>{words} words</span>
                <span className="text-outline-variant/60">·</span>
                <span>~{approxTokens} prompt tokens</span>
              </div>
            </div>
          </section>

          {/* 2. Runtime Guardrails & Boundary Control Card */}
          <section className="rounded-xl border border-outline-variant/50 bg-surface-container-lowest p-6 shadow-[0_4px_24px_-2px_rgba(42,42,40,0.04)] flex flex-col gap-6">
            <div className="flex items-center justify-between border-b border-surface-container-high pb-4">
              <div>
                <h2 className="text-headline-sm font-headline-sm text-on-surface font-serif">
                  Runtime Guardrails &amp; Boundary Control
                </h2>
                <p className="text-body-sm font-body-sm text-on-surface-variant mt-0.5">
                  Enforce deterministic kill-switches, financial limits, and supervisory checkpoints.
                </p>
              </div>
              <span className="px-2 py-0.5 rounded bg-surface-container-high text-on-surface-variant font-code-sm text-code-sm font-medium">
                Policy tier: STRICT-V2
              </span>
            </div>

            {/* Human Available Toggle Row */}
            <div className="flex items-start justify-between gap-4 p-4 rounded-lg bg-surface-container-low border border-outline-variant/30">
              <div className="flex gap-3">
                <div className="w-8 h-8 rounded-full bg-secondary/10 text-secondary flex items-center justify-center shrink-0 mt-0.5">
                  <span className="material-symbols-outlined text-base">verified_user</span>
                </div>
                <div className="flex flex-col">
                  <div className="flex items-center gap-2">
                    <span className="text-label-md font-label-md font-semibold text-on-surface">
                      Human-in-the-Loop Active
                    </span>
                    <span className="px-1.5 py-0.2 rounded text-label-sm font-label-sm bg-secondary-fixed text-on-secondary-fixed font-medium">
                      Recommended
                    </span>
                  </div>
                  <p className="text-body-sm font-body-sm text-on-surface-variant mt-1 leading-snug">
                    Pause execution and require manual operator sign-off before irreversible writes, external API mutations, or high-entropy shell tasks.
                  </p>
                </div>
              </div>

              {/* Toggle Component */}
              <label className="relative inline-flex items-center cursor-pointer shrink-0 mt-1">
                <input
                  type="checkbox"
                  checked={humanInLoop}
                  onChange={(e) => setHumanInLoop(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-surface-container-highest peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-outline-variant after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-secondary"></div>
              </label>
            </div>

            {/* Step Budget & Safety Limit Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Step Budget */}
              <div className="p-4 rounded-lg border border-outline-variant/30 bg-surface-container-low flex flex-col justify-between">
                <div className="flex justify-between items-center mb-1">
                  <label htmlFor="stepBudget" className="text-label-md font-label-md font-medium text-on-surface">
                    Step Budget Limit
                  </label>
                  <span className="text-code-sm font-code-sm text-on-surface-variant">Default: 50</span>
                </div>
                <p className="text-body-sm font-body-sm text-on-surface-variant mb-3">
                  Max iterations before autonomous loop forced termination.
                </p>
                <div className="flex items-center gap-2">
                  <div className="relative flex-1">
                    <input
                      id="stepBudget"
                      type="number"
                      min={1}
                      max={500}
                      value={stepBudget}
                      onChange={(e) => setStepBudget(Number(e.target.value) || 1)}
                      className="w-full px-3 py-1.5 rounded-lg border border-outline-variant/60 bg-surface-container-lowest text-on-surface font-code-md text-code-md focus:border-primary-container transition-colors focus:outline-none"
                    />
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      type="button"
                      onClick={() => setStepBudget((prev) => Math.max(1, prev - 5))}
                      className="w-8 h-8 rounded-md bg-surface-container-lowest border border-outline-variant/50 text-on-surface flex items-center justify-center hover:bg-surface-container transition-colors cursor-pointer"
                    >
                      <span className="material-symbols-outlined text-sm">remove</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setStepBudget((prev) => prev + 5)}
                      className="w-8 h-8 rounded-md bg-surface-container-lowest border border-outline-variant/50 text-on-surface flex items-center justify-center hover:bg-surface-container transition-colors cursor-pointer"
                    >
                      <span className="material-symbols-outlined text-sm">add</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* Compute Cap */}
              <div className="p-4 rounded-lg border border-outline-variant/30 bg-surface-container-low flex flex-col justify-between">
                <div className="flex justify-between items-center mb-1">
                  <label htmlFor="computeCap" className="text-label-md font-label-md font-medium text-on-surface">
                    Max Compute Cap
                  </label>
                  <span className="text-code-sm font-code-sm text-on-surface-variant">Hard Stop</span>
                </div>
                <p className="text-body-sm font-body-sm text-on-surface-variant mb-3">
                  Ceiling for token burn &amp; tool compute expenditure.
                </p>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-code-md font-code-md">
                    $
                  </span>
                  <input
                    id="computeCap"
                    type="text"
                    value={computeCap}
                    onChange={(e) => setComputeCap(e.target.value)}
                    className="w-full pl-7 pr-12 py-1.5 rounded-lg border border-outline-variant/60 bg-surface-container-lowest text-on-surface font-code-md text-code-md focus:border-primary-container transition-colors focus:outline-none"
                  />
                  <span className="absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-code-sm font-code-sm">
                    USD
                  </span>
                </div>
              </div>
            </div>

            {/* Supplementary Technical Parameters */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              {/* Model Architecture */}
              <div className="flex flex-col gap-1.5">
                <label
                  htmlFor="modelSelect"
                  className="text-label-md font-label-md font-medium text-on-surface flex items-center gap-1.5"
                >
                  <span className="material-symbols-outlined text-sm text-outline">smart_toy</span>
                  <span>Model Architecture</span>
                </label>
                <div className="relative">
                  <select
                    id="modelSelect"
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                    className="w-full appearance-none px-3 py-2 pr-8 rounded-lg border border-outline-variant/60 bg-surface-container-lowest text-body-sm font-body-sm text-on-surface focus:border-primary-container transition-colors focus:outline-none cursor-pointer"
                  >
                    <option>Claude 3.5 Sonnet (claude-3-5-sonnet-20241022)</option>
                    <option>Claude 3 Opus (claude-3-opus-20240229)</option>
                    <option>GPT-4o Runtime (gpt-4o-2024-08-06)</option>
                    <option>Llama 3.1 405B Instruct (Bedrock)</option>
                  </select>
                  <span className="material-symbols-outlined absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none text-on-surface-variant text-base">
                    expand_more
                  </span>
                </div>
                <div className="flex justify-between items-center text-code-sm font-code-sm text-on-surface-variant px-1 mt-0.5">
                  <span>Temp: 0.20 (deterministic)</span>
                  <span>Context: 200k</span>
                </div>
              </div>

              {/* Target Environment */}
              <div className="flex flex-col gap-1.5">
                <label
                  htmlFor="envSelect"
                  className="text-label-md font-label-md font-medium text-on-surface flex items-center gap-1.5"
                >
                  <span className="material-symbols-outlined text-sm text-outline">cloud_queue</span>
                  <span>Environment Target Tag</span>
                </label>
                <div className="relative">
                  <select
                    id="envSelect"
                    value={targetEnv}
                    onChange={(e) => setTargetEnv(e.target.value)}
                    className="w-full appearance-none px-3 py-2 pr-8 rounded-lg border border-outline-variant/60 bg-surface-container-lowest text-body-sm font-body-sm text-on-surface focus:border-primary-container transition-colors focus:outline-none cursor-pointer"
                  >
                    <option>staging-vpc-alpha (Sandboxed, Read/Branch Write)</option>
                    <option>data-pipeline-prod (Strict Multi-Approval Required)</option>
                    <option>local-eval-emulator (Air-gapped Mock)</option>
                  </select>
                  <span className="material-symbols-outlined absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none text-on-surface-variant text-base">
                    expand_more
                  </span>
                </div>
                <div className="flex justify-between items-center text-code-sm font-code-sm text-on-surface-variant px-1 mt-0.5">
                  <span>VPC Gateway: active</span>
                  <span className="text-secondary font-medium">Safe Mode: On</span>
                </div>
              </div>
            </div>
          </section>

          {/* 3. Pre-flight Telemetry Verification Inset */}
          <section className="rounded-lg border border-outline-variant/30 bg-surface-container p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-base text-primary">rule</span>
                <span className="text-label-md font-label-md font-medium text-on-surface">
                  Pre-flight Safety Interlock Checks
                </span>
              </div>
              <span className="text-label-sm font-label-sm text-secondary flex items-center gap-1 font-medium">
                <span className="material-symbols-outlined text-sm">check_circle</span>
                <span>All 4 Checks Passed</span>
              </span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-body-sm font-body-sm pt-1">
              <div className="bg-surface-container-lowest p-2 rounded border border-outline-variant/20 flex flex-col">
                <span className="text-label-sm font-label-sm text-on-surface-variant">Trace Logging</span>
                <span className="text-code-sm font-code-sm text-on-surface font-medium">
                  Full Stream (Level 0)
                </span>
              </div>
              <div className="bg-surface-container-lowest p-2 rounded border border-outline-variant/20 flex flex-col">
                <span className="text-label-sm font-label-sm text-on-surface-variant">Reversible Diffs</span>
                <span className="text-code-sm font-code-sm text-on-surface font-medium">
                  Auto-Snapshot Armed
                </span>
              </div>
              <div className="bg-surface-container-lowest p-2 rounded border border-outline-variant/20 flex flex-col">
                <span className="text-label-sm font-label-sm text-on-surface-variant">Rate Budget</span>
                <span className="text-code-sm font-code-sm text-on-surface font-medium">
                  40 req/min limit
                </span>
              </div>
              <div className="bg-surface-container-lowest p-2 rounded border border-outline-variant/20 flex flex-col">
                <span className="text-label-sm font-label-sm text-on-surface-variant">Entropy Ceiling</span>
                <span className="text-code-sm font-code-sm text-on-surface font-medium">
                  Score &lt; 0.42
                </span>
              </div>
            </div>
          </section>

          {/* 4. Launch Action Zone */}
          <div className="pt-4 flex flex-col sm:flex-row items-center justify-between gap-4 border-t border-outline-variant/40">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={onSimulateDryRun}
                className="px-4 py-2 rounded-lg bg-surface-container-lowest border border-outline-variant text-on-surface text-label-md font-label-md hover:bg-surface-container-low hover:text-on-surface active:scale-[0.99] transition-all flex items-center gap-1.5 cursor-pointer"
              >
                <span className="material-symbols-outlined text-base">play_arrow</span>
                <span>Simulate Dry-Run</span>
              </button>
              <button
                type="button"
                onClick={onSaveTemplate}
                className="px-3.5 py-2 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high/60 text-label-md font-label-md transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <span className="material-symbols-outlined text-base">bookmark_add</span>
                <span>Save as Template</span>
              </button>
            </div>

            {/* Primary Launch Agent Action Button */}
            <div className="flex items-center gap-3 w-full sm:w-auto">
              <button
                type="submit"
                className="w-full sm:w-auto px-6 py-2.5 rounded-lg bg-primary-container text-on-primary-container font-label-md text-label-md shadow-sm hover:opacity-95 active:scale-[0.99] transition-all flex items-center justify-center gap-2.5 cursor-pointer"
              >
                <span className="material-symbols-outlined text-base">rocket_launch</span>
                <span className="font-medium tracking-tight">Launch Agent</span>
                <span className="ml-1 px-1.5 py-0.5 rounded bg-on-primary-container/20 text-on-primary-container text-code-sm font-code-sm">
                  ⌘ ↵
                </span>
              </button>
            </div>
          </div>
        </form>

        {/* Editorial Footer Note */}
        <p className="text-center text-label-sm font-label-sm text-on-surface-variant/70 mt-12">
          Execution traces will stream continuously to the Execution Traces canvas. Operators retain non-blocking manual interrupt capability at every step.
        </p>
      </div>
    </main>
  );
};
