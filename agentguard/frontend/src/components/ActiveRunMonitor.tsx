import React, { useState } from 'react';
import { ActiveRunData, StepEvent } from '../types';
import { OLDER_STEPS_1_TO_10 } from '../data/mockData';

interface ActiveRunMonitorProps {
  run: ActiveRunData;
  onApproveStep: (stepNumber: number, action: string, guidance: string) => void;
  onResumeRun: () => void;
  onStepOnce: () => void;
  onForkRun: () => void;
}

export const ActiveRunMonitor: React.FC<ActiveRunMonitorProps> = ({
  run,
  onApproveStep,
  onResumeRun,
  onStepOnce,
  onForkRun
}) => {
  const [selectedInterventionAction, setSelectedInterventionAction] = useState<
    'approve' | 'modify' | 'reject'
  >('approve');
  const [operatorGuidance, setOperatorGuidance] = useState('');
  const [showOlderSteps, setShowOlderSteps] = useState(false);
  const [filterType, setFilterType] = useState<'all' | 'interventions' | 'tools'>('all');
  const [modifiedArgsCode, setModifiedArgsCode] = useState(
    `target='us-east-2',\nshard_id='shard_partition_004',\nrecords_count=25000,\nforce_overwrite=False,\nstaging_namespace='dry_run_sandbox'`
  );

  // Combine visible steps
  const allVisibleSteps: StepEvent[] = showOlderSteps
    ? [...run.steps, ...OLDER_STEPS_1_TO_10].sort((a, b) => b.stepNumber - a.stepNumber)
    : run.steps;

  // Filter steps based on filterType
  const filteredSteps = allVisibleSteps.filter((st) => {
    if (filterType === 'interventions') {
      return st.type === 'ASK_HUMAN' || st.type === 'DENY';
    }
    if (filterType === 'tools') {
      return (
        st.title.toLowerCase().includes('tool') ||
        st.title.toLowerCase().includes('cluster') ||
        st.title.toLowerCase().includes('auth') ||
        Boolean(st.payloadCode)
      );
    }
    return true;
  });

  const handleExecuteIntervention = () => {
    onApproveStep(18, selectedInterventionAction, operatorGuidance);
    setOperatorGuidance('');
  };

  return (
    <main className="flex-1 px-space-xl py-space-lg max-w-[1520px] w-full mx-auto space-y-space-lg">
      {/* SECTION 1: RUN IDENTITY & OBJECTIVE CARD */}
      <section className="bg-surface-container-lowest rounded-xl border border-outline-variant/40 p-space-lg shadow-[0_4px_24px_-2px_rgba(42,42,40,0.04)]">
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6">
          <div className="space-y-2.5 max-w-4xl">
            {/* Badges & Status Pill Row */}
            <div className="flex flex-wrap items-center gap-2.5">
              {run.status === 'PAUSED (AWAITING INPUT)' ? (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#FBF4E8] border border-[#EACD9B] text-[#805200] text-label-sm font-label-sm">
                  <span className="w-2 h-2 rounded-full bg-[#C98A2C] pulse-amber"></span>
                  <span className="tracking-wide">PAUSED (AWAITING INPUT)</span>
                </span>
              ) : run.status === 'RUNNING' ? (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-secondary-container/50 border border-secondary/30 text-secondary text-label-sm font-label-sm">
                  <span className="w-2 h-2 rounded-full bg-secondary animate-pulse"></span>
                  <span className="tracking-wide font-medium">RUNNING</span>
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-surface-container text-on-surface-variant text-label-sm font-label-sm">
                  <span className="w-2 h-2 rounded-full bg-secondary"></span>
                  <span className="tracking-wide">{run.status}</span>
                </span>
              )}

              <span className="text-label-sm font-label-sm text-on-surface-variant/80 font-code-sm bg-surface-container px-2 py-0.5 rounded border border-outline-variant/30">
                {run.agentId}
              </span>
              <span className="text-label-sm font-label-sm text-on-surface-variant/80 flex items-center gap-1">
                <span className="material-symbols-outlined text-[14px]">schedule</span>
                {run.startedTimeAgo}
              </span>
              <span className="text-label-sm font-label-sm text-on-surface-variant/80 flex items-center gap-1">
                <span className="material-symbols-outlined text-[14px]">psychology</span>
                {run.model}
              </span>
              <span className="text-label-sm font-label-sm text-on-surface-variant/80 flex items-center gap-1">
                <span className="material-symbols-outlined text-[14px]">hub</span>
                pipeline: {run.pipeline}
              </span>
            </div>

            {/* Prominent Agent Objective Headline in Newsreader Serif */}
            <h1 className="text-headline-lg font-headline-lg text-on-surface text-[28px] leading-[36px] tracking-tight font-serif">
              {run.objective}
            </h1>
            <p className="text-body-sm font-body-sm text-on-surface-variant leading-relaxed">
              {run.objectiveDescription}
            </p>
          </div>

          {/* Quick Action Buttons */}
          <div className="flex lg:flex-col items-end gap-2.5 shrink-0 self-start">
            <button
              onClick={onResumeRun}
              className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-primary text-on-primary hover:bg-[#833B24] text-label-md font-label-md transition-all shadow-sm active:scale-[0.99] font-medium cursor-pointer"
            >
              <span className="material-symbols-outlined text-[18px]">play_arrow</span>
              <span>{run.status === 'RUNNING' ? 'Pause Execution' : 'Resume Run'}</span>
            </button>
            <div className="flex items-center gap-2">
              <div className="relative group">
                <button
                  onClick={onStepOnce}
                  className="px-3 py-1.5 rounded-lg border border-outline-variant/60 bg-surface-container-lowest hover:bg-surface-container-low text-on-surface-variant text-label-sm font-label-sm transition-colors cursor-pointer flex items-center gap-1.5"
                >
                  Step Once
                  <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-outline-variant/30 text-on-surface-variant/50 border border-outline-variant/40 tracking-wide leading-none">U</span>
                </button>
                <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-[#1b1c1a] text-[#fcf9f5] text-[11px] rounded-lg shadow-lg whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                  Upcoming — not yet connected to backend
                </div>
              </div>
              <div className="relative group">
                <button
                  onClick={onForkRun}
                  className="px-3 py-1.5 rounded-lg border border-outline-variant/60 bg-surface-container-lowest hover:bg-surface-container-low text-on-surface-variant text-label-sm font-label-sm transition-colors cursor-pointer flex items-center gap-1.5"
                >
                  Fork Run
                  <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-outline-variant/30 text-on-surface-variant/50 border border-outline-variant/40 tracking-wide leading-none">U</span>
                </button>
                <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-[#1b1c1a] text-[#fcf9f5] text-[11px] rounded-lg shadow-lg whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                  Upcoming — not yet connected to backend
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 2: REFINED METRICS ROW */}
      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Steps Taken */}
        <div className="bg-surface-container-lowest p-space-md rounded-xl border border-outline-variant/40 shadow-[0_4px_24px_-2px_rgba(42,42,40,0.02)] flex flex-col justify-between">
          <div className="flex items-center justify-between text-on-surface-variant mb-2">
            <span className="text-label-sm font-label-sm tracking-wider uppercase">
              Steps Taken
            </span>
            <span className="material-symbols-outlined text-[16px]">footprint</span>
          </div>
          <div>
            <div className="flex items-baseline gap-2">
              <span className="font-code-md text-[20px] font-medium text-on-surface">
                {run.stepsTaken}
              </span>
              <span className="text-body-sm font-body-sm text-on-surface-variant">
                / {run.maxSteps} Max Steps
              </span>
            </div>
            {/* Slim terracotta progress bar */}
            <div className="w-full bg-surface-container rounded-full h-1.5 mt-2.5 overflow-hidden">
              <div
                className="bg-primary h-1.5 rounded-full transition-all duration-500"
                style={{ width: `${Math.min(100, (run.stepsTaken / run.maxSteps) * 100)}%` }}
              ></div>
            </div>
          </div>
          <div className="text-label-sm font-label-sm text-on-surface-variant/75 mt-2">
            {run.maxSteps - run.stepsTaken} steps remaining in budget
          </div>
        </div>

        {/* Metric 2: Compute & Budget */}
        <div className="bg-surface-container-lowest p-space-md rounded-xl border border-outline-variant/40 shadow-[0_4px_24px_-2px_rgba(42,42,40,0.02)] flex flex-col justify-between">
          <div className="flex items-center justify-between text-on-surface-variant mb-2">
            <span className="text-label-sm font-label-sm tracking-wider uppercase">
              Compute &amp; Budget
            </span>
            <span className="material-symbols-outlined text-[16px]">toll</span>
          </div>
          <div>
            <div className="flex items-baseline gap-2">
              <span className="font-code-md text-[20px] font-medium text-on-surface">
                ${run.computeCost.toFixed(2)}
              </span>
              <span className="text-body-sm font-body-sm text-on-surface-variant">
                used of ${run.computeCap.toFixed(2)} cap
              </span>
            </div>
            <div className="w-full bg-surface-container rounded-full h-1.5 mt-2.5 overflow-hidden">
              <div
                className="bg-tertiary h-1.5 rounded-full transition-all duration-500"
                style={{ width: `${Math.min(100, (run.computeCost / run.computeCap) * 100)}%` }}
              ></div>
            </div>
          </div>
          <div className="text-label-sm font-label-sm text-on-surface-variant/75 mt-2">
            {run.tokensProcessed.toLocaleString()} tokens processed (
            {Math.round((run.computeCost / run.computeCap) * 100)}%)
          </div>
        </div>

        {/* Metric 3: Elapsed Time / Latency */}
        <div className="bg-surface-container-lowest p-space-md rounded-xl border border-outline-variant/40 shadow-[0_4px_24px_-2px_rgba(42,42,40,0.02)] flex flex-col justify-between">
          <div className="flex items-center justify-between text-on-surface-variant mb-2">
            <span className="text-label-sm font-label-sm tracking-wider uppercase">
              Runtime &amp; Latency
            </span>
            <span className="material-symbols-outlined text-[16px]">timer</span>
          </div>
          <div>
            <div className="flex items-baseline gap-2">
              <span className="font-code-md text-[20px] font-medium text-on-surface">
                {run.runtimeFormatted}
              </span>
            </div>
            <div className="text-body-sm font-body-sm text-on-surface-variant mt-1 font-code-sm">
              avg {run.avgLatencyMs}ms / execution step
            </div>
          </div>
          <div className="text-label-sm font-label-sm text-secondary mt-2 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-secondary"></span>
            Within {run.latencyCeilingMs}ms latency ceiling
          </div>
        </div>

        {/* Metric 4: Intervention Triggers */}
        <div className="bg-[#FBF4E8] p-space-md rounded-xl border border-[#EACD9B] shadow-[0_4px_24px_-2px_rgba(42,42,40,0.02)] flex flex-col justify-between">
          <div className="flex items-center justify-between text-[#805200] mb-2">
            <span className="text-label-sm font-label-sm tracking-wider uppercase font-medium">
              Intervention Triggers
            </span>
            <span className="material-symbols-outlined text-[16px]">pan_tool</span>
          </div>
          <div>
            <div className="flex items-baseline gap-2">
              <span className="font-code-md text-[20px] font-semibold text-[#805200]">
                {run.interventionCount}{' '}
                {run.interventionCount === 1 ? 'Human Escalation' : 'Human Escalations'}
              </span>
            </div>
            <div className="text-body-sm font-body-sm text-[#805200]/80 mt-1">
              {run.activeInterventionStep
                ? `Active status: Step ${run.activeInterventionStep} blocked`
                : 'All interventions resolved'}
            </div>
          </div>
          <div className="text-label-sm font-label-sm text-[#805200] font-medium mt-2 flex items-center gap-1">
            <span className="material-symbols-outlined text-[14px]">warning</span>
            Sign-off mandatory for overwrite
          </div>
        </div>
      </section>

      {/* SECTION 3: MAIN LIVE TIMELINE & LOG WORKSPACE */}
      <section className="bg-surface-container-lowest rounded-xl border border-outline-variant/40 p-space-lg shadow-[0_4px_24px_-2px_rgba(42,42,40,0.04)]">
        {/* Timeline Section Header & Filter Cluster */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-space-md border-b border-outline-variant/30">
          <div>
            <h2 className="text-headline-sm font-headline-sm text-on-surface font-serif">
              Execution Narrative &amp; Action Timeline
            </h2>
            <p className="text-body-sm font-body-sm text-on-surface-variant">
              Continuous chronological ledger of agent thoughts, tool payloads, and policy evaluations.
            </p>
          </div>

          {/* Filters */}
          <div className="flex items-center bg-surface-container-low p-1 rounded-lg border border-outline-variant/40 text-label-sm font-label-sm">
            <button
              onClick={() => setFilterType('all')}
              className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                filterType === 'all'
                  ? 'bg-surface-container-lowest shadow-sm text-on-surface font-medium'
                  : 'text-on-surface-variant hover:text-on-surface'
              }`}
            >
              All Steps ({showOlderSteps ? 18 : 5})
            </button>
            <button
              onClick={() => setFilterType('interventions')}
              className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1 cursor-pointer ${
                filterType === 'interventions'
                  ? 'bg-surface-container-lowest shadow-sm text-on-surface font-medium'
                  : 'text-on-surface-variant hover:text-on-surface'
              }`}
            >
              <span>Interventions</span>
              <span className="w-4 h-4 rounded-full bg-[#FBF4E8] text-[#805200] text-[10px] inline-flex items-center justify-center font-bold">
                {run.interventionCount}
              </span>
            </button>
            <button
              onClick={() => setFilterType('tools')}
              className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                filterType === 'tools'
                  ? 'bg-surface-container-lowest shadow-sm text-on-surface font-medium'
                  : 'text-on-surface-variant hover:text-on-surface'
              }`}
            >
              Tool Invocations (8)
            </button>
          </div>
        </div>

        {/* The Timeline Canvas */}
        <div className="relative pt-6">
          {/* Continuous Vertical Spine Connecting Timeline Nodes */}
          <div className="absolute left-[19px] top-8 bottom-6 w-[2px] bg-surface-container-highest"></div>

          <div className="space-y-8">
            {filteredSteps.map((step) => {
              // ASK_HUMAN STEP
              if (step.type === 'ASK_HUMAN') {
                return (
                  <div key={step.id} className="relative flex gap-5">
                    {/* Timeline Amber Node Marker */}
                    <div className="relative z-10 w-10 h-10 rounded-full bg-[#FBF4E8] border-2 border-[#C98A2C] flex items-center justify-center text-[#C98A2C] shadow-sm shrink-0">
                      <span className="w-3 h-3 rounded-full bg-[#C98A2C] pulse-amber"></span>
                    </div>

                    {/* Content Body */}
                    <div className="flex-1 bg-surface-container-low rounded-xl border border-[#EACD9B] p-space-md space-y-4 shadow-[0_4px_16px_-2px_rgba(201,138,44,0.08)]">
                      {/* Step Header */}
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-outline-variant/30 pb-3">
                        <div className="flex items-center gap-2.5">
                          <span className="text-label-sm font-label-sm font-code-sm uppercase px-2 py-0.5 rounded bg-[#FBF4E8] text-[#805200] border border-[#EACD9B] font-semibold">
                            ASK_HUMAN
                          </span>
                          <h3 className="text-body-md font-body-md font-semibold text-on-surface">
                            {step.title}
                          </h3>
                        </div>
                        <div className="flex items-center gap-2 text-label-sm font-label-sm text-on-surface-variant">
                          <span className="material-symbols-outlined text-[14px]">schedule</span>
                          <span>{step.timeAgo}</span>
                          <span>•</span>
                          <span className="font-code-sm">id: {step.id}</span>
                        </div>
                      </div>

                      {/* Agent Reasoning / Thought Trace */}
                      <div className="space-y-1.5">
                        <div className="text-label-sm font-label-sm text-on-surface-variant uppercase tracking-wider">
                          Agent Internal Reasoning
                        </div>
                        <p className="text-body-md font-body-md text-on-surface leading-relaxed italic bg-surface-container-lowest/80 p-3 rounded-lg border border-outline-variant/30">
                          {step.reasoning}
                        </p>
                      </div>

                      {/* Proposed Tool Call Monospace Box */}
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between text-label-sm font-label-sm text-on-surface-variant">
                          <span className="uppercase tracking-wider">
                            Proposed Tool Execution Payload
                          </span>
                          <span className="font-code-sm text-code-sm text-primary">
                            cluster.exec_partition_transfer
                          </span>
                        </div>
                        <div className="bg-surface-container-lowest rounded-lg p-3 border border-outline-variant/40 font-code-sm text-code-sm text-on-surface overflow-x-auto">
                          <span className="text-primary font-medium">
                            cluster.exec_partition_transfer
                          </span>
                          (<br />
                          &nbsp;&nbsp;target=
                          <span className="text-secondary">'us-east-2'</span>,<br />
                          &nbsp;&nbsp;shard_id=
                          <span className="text-secondary">'shard_partition_004'</span>,<br />
                          &nbsp;&nbsp;records_count=
                          <span className="text-tertiary">50000</span>,<br />
                          &nbsp;&nbsp;force_overwrite=
                          <span className="text-error font-medium">False</span>
                          <br />)
                        </div>
                      </div>

                      {/* Human Intervention Prompt Box */}
                      <div className="bg-surface-container-lowest rounded-lg border border-outline-variant/50 p-4 space-y-3">
                        <div className="flex items-center gap-2 text-label-md font-label-md text-on-surface font-semibold">
                          <span className="material-symbols-outlined text-[18px] text-[#C98A2C]">
                            gavel
                          </span>
                          <span>Human Operator Sign-Off Required</span>
                        </div>

                        {/* Radio Selection Group */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
                          <label
                            onClick={() => setSelectedInterventionAction('approve')}
                            className={`flex items-start gap-2.5 p-2.5 rounded-lg border cursor-pointer transition-colors ${
                              selectedInterventionAction === 'approve'
                                ? 'border-primary/40 bg-primary-fixed/20'
                                : 'border-outline-variant/40 bg-surface-container-low hover:bg-surface-container'
                            }`}
                          >
                            <input
                              type="radio"
                              name="intervention_action"
                              checked={selectedInterventionAction === 'approve'}
                              onChange={() => setSelectedInterventionAction('approve')}
                              className="mt-0.5 text-primary focus:ring-primary"
                            />
                            <div>
                              <div className="text-label-sm font-label-sm font-semibold text-on-surface">
                                Approve &amp; Resume
                              </div>
                              <div className="text-[11px] text-on-surface-variant leading-tight">
                                Execute tool with current payload
                              </div>
                            </div>
                          </label>

                          <label
                            onClick={() => setSelectedInterventionAction('modify')}
                            className={`flex items-start gap-2.5 p-2.5 rounded-lg border cursor-pointer transition-colors ${
                              selectedInterventionAction === 'modify'
                                ? 'border-primary/40 bg-primary-fixed/20'
                                : 'border-outline-variant/40 bg-surface-container-low hover:bg-surface-container'
                            }`}
                          >
                            <input
                              type="radio"
                              name="intervention_action"
                              checked={selectedInterventionAction === 'modify'}
                              onChange={() => setSelectedInterventionAction('modify')}
                              className="mt-0.5 text-primary focus:ring-primary"
                            />
                            <div>
                              <div className="text-label-sm font-label-sm font-semibold text-on-surface">
                                Modify Args
                              </div>
                              <div className="text-[11px] text-on-surface-variant leading-tight">
                                Edit parameter values safely
                              </div>
                            </div>
                          </label>

                          <label
                            onClick={() => setSelectedInterventionAction('reject')}
                            className={`flex items-start gap-2.5 p-2.5 rounded-lg border cursor-pointer transition-colors ${
                              selectedInterventionAction === 'reject'
                                ? 'border-error/40 bg-error-container/30'
                                : 'border-outline-variant/40 bg-surface-container-low hover:bg-surface-container'
                            }`}
                          >
                            <input
                              type="radio"
                              name="intervention_action"
                              checked={selectedInterventionAction === 'reject'}
                              onChange={() => setSelectedInterventionAction('reject')}
                              className="mt-0.5 text-primary focus:ring-primary"
                            />
                            <div>
                              <div className="text-label-sm font-label-sm font-semibold text-on-surface">
                                Reject Step
                              </div>
                              <div className="text-[11px] text-on-surface-variant leading-tight">
                                Abort step and provide prompt hint
                              </div>
                            </div>
                          </label>
                        </div>

                        {/* If Modify Args is active, show argument editor */}
                        {selectedInterventionAction === 'modify' && (
                          <div className="space-y-1.5 p-2.5 bg-surface-container-low rounded-lg border border-outline-variant/40">
                            <div className="text-label-sm font-label-sm text-on-surface font-medium flex items-center justify-between">
                              <span>Editable Arguments (Python kwargs)</span>
                              <span className="text-code-sm text-primary font-normal">
                                Sanitized &amp; Validated
                              </span>
                            </div>
                            <textarea
                              rows={3}
                              value={modifiedArgsCode}
                              onChange={(e) => setModifiedArgsCode(e.target.value)}
                              className="w-full font-code-sm text-code-sm p-2 rounded bg-surface-container-lowest border border-outline-variant/40 text-on-surface focus:outline-none focus:border-primary"
                            />
                          </div>
                        )}

                        {/* Operator Quick-Reply Guidance Input */}
                        <div className="flex flex-col sm:flex-row gap-2 pt-1">
                          <input
                            type="text"
                            value={operatorGuidance}
                            onChange={(e) => setOperatorGuidance(e.target.value)}
                            placeholder={
                              selectedInterventionAction === 'reject'
                                ? "Specify rejection reason / recovery instructions (e.g. 'Use replica snapshot first')..."
                                : "Add optional operator guidance (e.g. 'Use sandbox staging namespace first')..."
                            }
                            className="flex-1 rounded-lg border border-outline-variant/60 bg-surface-container-lowest px-3 py-2 text-body-sm font-body-sm text-on-surface focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary placeholder:text-on-surface-variant/50"
                          />
                          <button
                            onClick={handleExecuteIntervention}
                            className={`px-4 py-2 rounded-lg text-label-md font-label-md font-medium transition-colors shadow-sm shrink-0 flex items-center justify-center gap-1.5 cursor-pointer ${
                              selectedInterventionAction === 'reject'
                                ? 'bg-error hover:bg-[#8f1313] text-on-error'
                                : 'bg-primary hover:bg-[#833B24] text-on-primary'
                            }`}
                          >
                            <span className="material-symbols-outlined text-[16px]">
                              {selectedInterventionAction === 'reject'
                                ? 'cancel'
                                : 'check_circle'}
                            </span>
                            <span>
                              {selectedInterventionAction === 'reject'
                                ? 'Reject & Re-route'
                                : selectedInterventionAction === 'modify'
                                ? 'Approve with Modifications'
                                : 'Approve Step'}
                            </span>
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              }

              // DENY / INTERCEPTED STEP
              if (step.type === 'DENY') {
                return (
                  <div key={step.id} className="relative flex gap-5">
                    {/* Muted Brick-Red Node */}
                    <div className="relative z-10 w-10 h-10 rounded-full bg-[#F9EBE9] border-2 border-[#B34A3E] flex items-center justify-center text-[#B34A3E] shadow-sm shrink-0">
                      <span className="material-symbols-outlined text-[18px]">block</span>
                    </div>

                    {/* Content Body */}
                    <div className="flex-1 bg-surface-container-lowest rounded-xl border border-error/30 p-space-md space-y-3 bg-[#FDFCFA]">
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-error/15 pb-2.5">
                        <div className="flex items-center gap-2">
                          <span className="text-label-sm font-label-sm font-code-sm uppercase px-2 py-0.5 rounded bg-[#F9EBE9] text-[#B34A3E] border border-[#B34A3E]/30 font-semibold">
                            DENY / INTERCEPTED
                          </span>
                          <h3 className="text-body-md font-body-md font-medium text-[#B34A3E]">
                            {step.title}
                          </h3>
                        </div>
                        <span className="text-label-sm font-label-sm text-on-surface-variant">
                          {step.timeAgo}
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-[#F9EBE9]/40 border border-[#B34A3E]/20 text-body-sm font-body-sm text-on-surface space-y-1">
                        <div className="font-medium text-[#B34A3E] flex items-center gap-1.5">
                          <span className="material-symbols-outlined text-[16px]">shield_lock</span>
                          <span>Guardrail Interception: Policy [SEC-049: FileSystemIsolation]</span>
                        </div>
                        <p className="text-on-surface-variant leading-relaxed">
                          Action denied automatically: Agent attempted direct write to system path{' '}
                          <code className="font-code-sm text-code-sm bg-surface-container-high px-1 py-0.5 rounded text-on-surface">
                            /etc/hosts
                          </code>{' '}
                          to adjust host aliases. Tripwire halted the attempt; agent safely auto-remediated towards ephemeral virtual scratchpad.
                        </p>
                      </div>

                      <div className="flex items-center justify-between text-label-sm font-label-sm text-on-surface-variant pt-0.5">
                        <span className="font-code-sm">Tripwire: {step.tripwireRule || 'rule_no_host_tamper'}</span>
                        <span className="text-[#4A7C59] flex items-center gap-1 font-medium">
                          <span className="material-symbols-outlined text-[14px]">auto_fix_high</span>
                          Self-correction succeeded
                        </span>
                      </div>
                    </div>
                  </div>
                );
              }

              // ALLOW STEP
              return (
                <div key={step.id} className="relative flex gap-5">
                  {/* Sage Green Node */}
                  <div className="relative z-10 w-10 h-10 rounded-full bg-[#E8F0EA] border-2 border-secondary flex items-center justify-center text-secondary shadow-sm shrink-0">
                    <span className="w-2.5 h-2.5 rounded-full bg-secondary"></span>
                  </div>

                  {/* Content Body */}
                  <div className="flex-1 bg-surface-container-lowest rounded-xl border border-outline-variant/40 p-space-md space-y-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-label-sm font-label-sm font-code-sm uppercase px-2 py-0.5 rounded bg-[#E8F0EA] text-[#2F5B3D] border border-secondary/30 font-medium">
                          ALLOW
                        </span>
                        <h3 className="text-body-md font-body-md font-medium text-on-surface">
                          {step.title}
                        </h3>
                      </div>
                      <span className="text-label-sm font-label-sm text-on-surface-variant">
                        {step.timeAgo}
                      </span>
                    </div>

                    {step.reasoning && (
                      <p className="text-body-sm font-body-sm text-on-surface-variant">
                        {step.reasoning}
                      </p>
                    )}

                    {step.responsePreview && (
                      <div className="bg-surface-container-low rounded-lg p-2.5 border border-outline-variant/30 font-code-sm text-code-sm text-on-surface">
                        <span className="text-secondary font-medium">response: </span>
                        {step.responsePreview}
                      </div>
                    )}

                    {step.metadata && (
                      <div className="bg-surface-container-low rounded-lg p-2.5 border border-outline-variant/30 font-code-sm text-code-sm text-on-surface flex items-center justify-between">
                        <span>role_arn: "arn:aws:iam::10492817291:role/VectorMigrationAgentScopedRole"</span>
                        <span className="text-secondary text-label-sm font-label-sm font-medium">
                          TTL: {step.metadata.ttl}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Older steps toggle button */}
          {!showOlderSteps && (
            <div className="pl-14 pt-6">
              <button
                onClick={() => setShowOlderSteps(true)}
                className="flex items-center gap-2 text-label-sm font-label-sm text-on-surface-variant hover:text-on-surface transition-colors py-1.5 px-3 rounded-lg border border-outline-variant/40 bg-surface-container-low hover:bg-surface-container cursor-pointer"
              >
                <span className="material-symbols-outlined text-[16px]">history</span>
                <span>Load Steps 1 through 10 (Initialization &amp; Handshake)</span>
              </button>
            </div>
          )}
        </div>
      </section>

      {/* Refined Editorial Document Footer */}
      <footer className="mt-auto px-space-xl py-space-md border-t border-outline-variant/30 flex flex-col sm:flex-row items-center justify-between gap-4 text-label-sm font-label-sm text-on-surface-variant/75 bg-surface-bright rounded-lg">
        <div className="flex items-center gap-3">
          <span>AgentGuard Runtime v2.14.0-prod</span>
          <span>•</span>
          <span>Cluster: us-east-2.core.control</span>
          <span>•</span>
          <span>
            Audit Session: <code className="font-code-sm text-code-sm">aud_8492_99a</code>
          </span>
        </div>
        <div>Human-in-the-Loop Active Oversight Enabled</div>
      </footer>
    </main>
  );
};
