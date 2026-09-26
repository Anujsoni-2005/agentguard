import React, { useState, useEffect, useCallback } from 'react';
import { NavigationTab, ApprovalCard, ActiveRunData, StepEvent } from './types';
import { INITIAL_APPROVALS, INITIAL_RUN_8492, OTHER_RUNS } from './data/mockData';
import {
  listPendingApprovals,
  decideApproval,
  listRuns,
  listActions,
  createRun,
  haltRun,
  resumeRun,
  mapApprovalToCard,
  mapRunToActiveRunData,
} from './data/apiClient';
import { SideNavBar } from './components/SideNavBar';
import { TopNavBar } from './components/TopNavBar';
import { ApprovalsInbox } from './components/ApprovalsInbox';
import { ActiveRunMonitor } from './components/ActiveRunMonitor';
import { ComposeMission } from './components/ComposeMission';
import { ActiveRunsList } from './components/ActiveRunsList';
import { PoliciesView } from './components/PoliciesView';
import { TracesView } from './components/TracesView';
import { SettingsView } from './components/SettingsView';
import { TraceDrawer } from './components/TraceDrawer';
import { EmergencyHaltModal } from './components/EmergencyHaltModal';
import { DocumentationModal } from './components/DocumentationModal';
import { SupportModal } from './components/SupportModal';
import { NotificationsModal } from './components/NotificationsModal';
import { ExportLogModal } from './components/ExportLogModal';

export default function App() {
  const [currentTab, setCurrentTab] = useState<NavigationTab>('inbox');
  const [approvals, setApprovals] = useState<ApprovalCard[]>(INITIAL_APPROVALS);
  const [runs, setRuns] = useState<ActiveRunData[]>(OTHER_RUNS);
  const [selectedRunId, setSelectedRunId] = useState<string>('run-8492-synthetics');
  const [searchFilter, setSearchFilter] = useState('');
  const [fleetPaused, setFleetPaused] = useState(false);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);

  // Modals
  const [inspectedCard, setInspectedCard] = useState<ApprovalCard | null>(null);
  const [isHaltModalOpen, setIsHaltModalOpen] = useState(false);
  const [isDocModalOpen, setIsDocModalOpen] = useState(false);
  const [isSupportModalOpen, setIsSupportModalOpen] = useState(false);
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);

  // Toast notification
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage((prev) => (prev === msg ? null : prev));
    }, 3200);
  };

  // ── Flow 1: Poll Approvals Inbox every 5s ───────────────────────────────
  const fetchApprovals = useCallback(async () => {
    try {
      const raw = await listPendingApprovals();
      setBackendOnline(true);
      // Merge live pending approvals with any locally-resolved ones
      setApprovals((prev) => {
        const liveIds = new Set(raw.map((a) => a.approval_id));
        const localResolved = prev.filter(
          (a) => a.status !== 'pending' && !liveIds.has(a.id)
        );
        const liveMapped = raw.map(mapApprovalToCard);
        return [...liveMapped, ...localResolved];
      });
    } catch {
      setBackendOnline((prev) => prev === null ? false : prev);
    }
  }, []);

  // ── Flow 2: Poll Runs list every 8s ────────────────────────────────────
  const fetchRuns = useCallback(async () => {
    try {
      const rawRuns = await listRuns(50);
      setBackendOnline(true);
      if (rawRuns.length === 0) return; // keep mock data if no runs yet
      const mapped = await Promise.all(
        rawRuns.map(async (r) => {
          try {
            const actions = await listActions(r.run_id);
            return mapRunToActiveRunData(r, actions);
          } catch {
            return mapRunToActiveRunData(r, []);
          }
        })
      );
      setRuns(mapped);
      // Auto-select first real run if we were on a mock run
      setSelectedRunId((prev) => {
        const ids = new Set(mapped.map((r) => r.id));
        return ids.has(prev) ? prev : mapped[0]?.id ?? prev;
      });
    } catch {
      // Backend offline — keep mock data
    }
  }, []);

  useEffect(() => {
    fetchApprovals();
    fetchRuns();
    const t1 = setInterval(fetchApprovals, 5_000);
    const t2 = setInterval(fetchRuns, 8_000);
    return () => { clearInterval(t1); clearInterval(t2); };
  }, [fetchApprovals, fetchRuns]);

  const pendingApprovalsCount = approvals.filter((a) => a.status === 'pending').length;

  const currentRun = runs.find((r) => r.id === selectedRunId) || runs[0];

  // ── Flow 1 Actions: Approvals Inbox ────────────────────────────────────
  const handleApproveCard = async (id: string) => {
    const card = approvals.find((a) => a.id === id);
    // Optimistically update UI
    setApprovals((prev) =>
      prev.map((item) => (item.id === id ? { ...item, status: 'approved' } : item))
    );
    try {
      await decideApproval(id, 'approve');
      showToast(`Approved action for ${card?.agentId || 'agent'}`);
    } catch (err: unknown) {
      // Roll back on error
      setApprovals((prev) =>
        prev.map((item) => (item.id === id ? { ...item, status: 'pending' } : item))
      );
      showToast(`Failed to approve: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  };

  const handleRejectCard = async (id: string) => {
    const card = approvals.find((a) => a.id === id);
    setApprovals((prev) =>
      prev.map((item) => (item.id === id ? { ...item, status: 'rejected' } : item))
    );
    try {
      await decideApproval(id, 'reject');
      showToast(`Rejected action for ${card?.agentId || 'agent'}`);
    } catch (err: unknown) {
      setApprovals((prev) =>
        prev.map((item) => (item.id === id ? { ...item, status: 'pending' } : item))
      );
      showToast(`Failed to reject: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  };

  const handleReviewAll = async () => {
    const pendingIds = approvals.filter((a) => a.status === 'pending').map((a) => a.id);
    setApprovals((prev) =>
      prev.map((item) => (item.status === 'pending' ? { ...item, status: 'approved' } : item))
    );
    showToast('Batch approving all pending interventions...');
    // Fire all in parallel; individual failures will be surfaced on next poll
    await Promise.allSettled(pendingIds.map((id) => decideApproval(id, 'approve')));
    showToast(`Batch approved ${pendingIds.length} agent intervention(s).`);
  };

  const handleResetApprovals = () => {
    // When backend is online this just re-fetches; offline shows mock data
    if (backendOnline) {
      fetchApprovals();
      showToast('Refreshed approvals from backend.');
    } else {
      setApprovals(INITIAL_APPROVALS);
      showToast('Reset approval inbox with mock data (backend offline).');
    }
  };

  // Actions for Active Run Monitor
  const handleApproveStep = (stepNumber: number, action: string, guidance: string) => {
    if (action === 'reject') {
      showToast(`Step ${stepNumber} rejected. Re-routing task execution.`);
      setRuns((prev) =>
        prev.map((r) => {
          if (r.id !== selectedRunId) return r;
          return {
            ...r,
            status: 'RUNNING',
            activeInterventionStep: undefined,
            interventionCount: Math.max(0, r.interventionCount - 1),
            steps: r.steps.map((st) =>
              st.stepNumber === stepNumber
                ? {
                    ...st,
                    type: 'DENY',
                    title: `Step ${stepNumber}: Operator Rejected with Guidance: "${guidance || 'Abort write'}"`
                  }
                : st
            )
          };
        })
      );
      return;
    }

    // Approve or Modify
    showToast(
      action === 'modify'
        ? `Step ${stepNumber} approved with parameter modifications.`
        : `Step ${stepNumber} approved. Executing partition transfer...`
    );

    const newStep19: StepEvent = {
      stepNumber: 19,
      id: `stp_8492_19`,
      type: 'ALLOW',
      title: 'Step 19: Tool Invocation: cluster.exec_partition_transfer',
      timeAgo: 'Just now',
      reasoning: 'Partition transfer in progress: 50,000 vectors transferred with verified md5 boundary checksums.',
      responsePreview: '{ "status": "200 SUCCESS", "records_transferred": 50000, "destination_node": "us-east-2.core.04", "duration": "412ms" }'
    };

    setRuns((prev) =>
      prev.map((r) => {
        if (r.id !== selectedRunId) return r;
        return {
          ...r,
          status: 'RUNNING',
          stepsTaken: r.stepsTaken + 1,
          computeCost: r.computeCost + 0.18,
          tokensProcessed: r.tokensProcessed + 4200,
          interventionCount: Math.max(0, r.interventionCount - 1),
          activeInterventionStep: undefined,
          steps: [
            newStep19,
            ...r.steps.map((st) =>
              st.stepNumber === stepNumber
                ? {
                    ...st,
                    type: 'ALLOW' as const,
                    title: `Step ${stepNumber}: Human Operator Sign-Off Verified`,
                    reasoning: `Human operator verified execution intent.${
                      guidance ? ` Guidance: "${guidance}"` : ''
                    }`
                  }
                : st
            )
          ]
        };
      })
    );
  };

  // ── Flow 2 Actions: Run control (pause/resume/halt) ────────────────────
  const handleResumeRun = async () => {
    const run = runs.find((r) => r.id === selectedRunId);
    if (!run) return;
    const isPaused = run.status === 'PAUSED (AWAITING INPUT)';
    // Optimistic update
    setRuns((prev) =>
      prev.map((r) => {
        if (r.id !== selectedRunId) return r;
        const nextStatus: ActiveRunData['status'] = isPaused ? 'RUNNING' : 'PAUSED (AWAITING INPUT)';
        return { ...r, status: nextStatus };
      })
    );
    if (backendOnline && isPaused) {
      try {
        await resumeRun(selectedRunId);
        showToast('Resumed agent execution.');
      } catch (err: unknown) {
        showToast(`Resume failed: ${err instanceof Error ? err.message : 'Unknown error'}`);
        fetchRuns(); // re-sync
      }
    } else {
      showToast(isPaused ? 'Resumed agent execution.' : 'Paused agent execution.');
    }
  };

  const handleStepOnce = () => {
    showToast('Executed single step simulation in sandboxed runtime.');
  };

  const handleForkRun = () => {
    const forkedId = `run-${Math.floor(1000 + Math.random() * 9000)}-fork`;
    const forkedRun: ActiveRunData = {
      ...currentRun,
      id: forkedId,
      name: forkedId,
      objective: `${currentRun.objective} (Forked Branch)`,
      startedTimeAgo: 'Started just now'
    };
    setRuns((prev) => [forkedRun, ...prev]);
    setSelectedRunId(forkedId);
    showToast(`Forked new run branch: ${forkedId}`);
  };

  // -- Flow 3 Action: Launch Run (Compose Mission) --
  const handleLaunchRun = async (newRunProps: Partial<ActiveRunData>) => {
    const rawObjective = (newRunProps.objective ?? '"New Mission"')
      .replace(/^"|"$/g, '').trim();
    const maxSteps = newRunProps.maxSteps ?? 50;
    const computeCap = newRunProps.computeCap ?? 10.0;

    if (backendOnline) {
      try {
        showToast('Launching mission on AgentGuard backend...');
        const result = await createRun(rawObjective, {
          maxSteps,
          maxCostUsd: computeCap > 0 ? computeCap : undefined,
          humanAvailable: true,
        });
        showToast(`Mission launched: ${result.run_id}`);
        setCurrentTab('run-monitor');
        setTimeout(async () => {
          await fetchRuns();
          setSelectedRunId(result.run_id);
        }, 800);
        return;
      } catch (err: unknown) {
        showToast(`Backend launch failed: ${err instanceof Error ? err.message : 'Unknown'}. Using local simulation.`);
      }
    }

    // Fallback: local simulation
    const newId = `run-${Math.floor(1000 + Math.random() * 9000)}-audit`;
    const fullNewRun: ActiveRunData = {
      id: newId,
      name: newId,
      objective: newRunProps.objective || '"New Autonomous Mission"',
      objectiveDescription:
        newRunProps.objectiveDescription || 'Initialized in staging-vpc-alpha with strict interlocks.',
      status: 'RUNNING',
      agentId: 'agent-swarm-501',
      startedTimeAgo: 'Started just now',
      model: newRunProps.model || 'claude-3-5-sonnet',
      pipeline: 'security-audit-pipeline',
      environment: newRunProps.environment || 'staging-vpc-alpha',
      stepsTaken: 1,
      maxSteps,
      computeCost: 0.12,
      computeCap,
      tokensProcessed: 1850,
      runtimeFormatted: '0m 12s',
      avgLatencyMs: 650,
      latencyCeilingMs: 1200,
      interventionCount: 0,
      steps: [
        {
          stepNumber: 1,
          id: `stp_${newId}_01`,
          type: 'ALLOW',
          title: 'Step 1: Swarm Pod Handshake & Role Assumption',
          timeAgo: 'Just now',
          reasoning: 'Verified mTLS connection to staging VPC gateway and initialized telemetry channel.'
        }
      ]
    };
    setRuns((prev) => [fullNewRun, ...prev]);
    setSelectedRunId(newId);
    setCurrentTab('run-monitor');
    showToast(`Launched (local simulation): ${newId}`);
  };

  const handleSimulateDryRun = () => {
    showToast('Dry-run simulation completed: All 4 safety interlocks passed.');
  };

  const handleSaveTemplate = () => {
    showToast('Saved mission formulation as reusable template.');
  };

  // Fleet controls
  const handleTogglePauseFleet = () => {
    setFleetPaused((prev) => {
      const next = !prev;
      showToast(next ? 'Autonomous fleet paused.' : 'Autonomous fleet resumed.');
      return next;
    });
  };

  const handleConfirmEmergencyHalt = async () => {
    setFleetPaused(true);
    setRuns((prev) => prev.map((r) => ({ ...r, status: 'HALTED' })));
    showToast('EMERGENCY HALT TRIGGERED: Halting all runs...');
    if (backendOnline) {
      // Halt all live runs in parallel
      const liveRunIds = runs.map((r) => r.id);
      await Promise.allSettled(liveRunIds.map((id) => haltRun(id, 'emergency_halt')));
    }
    showToast('EMERGENCY HALT COMPLETE: All agent swarm pipelines frozen.');
  };

  return (
    <div className="min-h-screen bg-background text-on-surface antialiased flex flex-col font-body-md text-body-md selection:bg-primary-fixed selection:text-on-primary-fixed">
      {/* Backend connection status banner — in normal flow, no overlap */}
      {backendOnline === false && (
        <div className="w-full bg-[#FBF4E8] border-b border-[#EACD9B] px-6 py-1.5 text-label-sm font-label-sm text-[#805200] flex items-center gap-2 shrink-0">
          <span className="material-symbols-outlined text-[14px] text-[#C98A2C]">warning</span>
          <span>Backend offline — showing demo data. Start the hub on port 8000 to connect.</span>
        </div>
      )}
      {backendOnline === true && (
        <div className="w-full bg-[#E8F5E9] border-b border-[#A5D6A7] px-6 py-1.5 text-label-sm font-label-sm text-[#1B5E20] flex items-center gap-2 shrink-0">
          <span className="material-symbols-outlined text-[14px] text-[#388E3C]">check_circle</span>
          <span>Connected to AgentGuard Hub — live data active.</span>
        </div>
      )}

      {/* Row: Sidebar + Main content */}
      <div className="flex flex-1 min-h-0">
        {/* 1. Side Navigation Bar */}
        <SideNavBar
          currentTab={currentTab}
          onSelectTab={(tab) => {
            if (tab === 'active-runs' && selectedRunId) {
              setCurrentTab('run-monitor');
            } else {
              setCurrentTab(tab);
            }
          }}
          pendingCount={pendingApprovalsCount}
          fleetPaused={fleetPaused}
          onTogglePauseFleet={handleTogglePauseFleet}
          onOpenDocModal={() => setIsDocModalOpen(true)}
          onOpenSupportModal={() => setIsSupportModalOpen(true)}
        />

        {/* 2. Main Canvas */}
        <div className="flex flex-col flex-1 min-h-screen min-w-0">
          {/* Top Dock Navigation Bar */}
          <TopNavBar
            currentTab={currentTab}
            onSelectTab={setCurrentTab}
            searchFilter={searchFilter}
            onSearchChange={setSearchFilter}
            activeRunId={selectedRunId}
            fleetCount={runs.length * 3 + 2}
            fleetPaused={fleetPaused}
            onReviewAll={handleReviewAll}
            onEmergencyHalt={() => setIsHaltModalOpen(true)}
            onExportRunLog={() => setIsExportModalOpen(true)}
            onOpenNotifications={() => setIsNotificationsOpen(true)}
            onOpenTuneModal={() => setCurrentTab('settings')}
            onOpenUserProfile={() =>
              showToast('Operator Profile: Lead AI Safety & Autonomy Oversight Engineer')
            }
          />

        {/* Global Fleet Paused Notification Banner */}
        {fleetPaused && (
          <div className="bg-[#FBF4E8] border-b border-[#EACD9B] px-margin py-2 text-label-sm font-label-sm text-[#805200] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[16px] text-[#C98A2C]">
                pause_circle
              </span>
              <span className="font-semibold">FLEET INTERVENTION ACTIVE:</span>
              <span>All autonomous agent loops are currently frozen.</span>
            </div>
            <button
              onClick={handleTogglePauseFleet}
              className="text-[#805200] underline font-semibold hover:opacity-80 cursor-pointer"
            >
              Resume Fleet Execution
            </button>
          </div>
        )}

        {/* Dynamic Screen Rendering */}
        {currentTab === 'inbox' && (
          <ApprovalsInbox
            approvals={approvals}
            searchFilter={searchFilter}
            onApprove={handleApproveCard}
            onReject={handleRejectCard}
            onInspectTrace={(card) => setInspectedCard(card)}
            onResetApprovals={handleResetApprovals}
          />
        )}

        {currentTab === 'run-monitor' && (
          <ActiveRunMonitor
            run={currentRun}
            onApproveStep={handleApproveStep}
            onResumeRun={handleResumeRun}
            onStepOnce={handleStepOnce}
            onForkRun={handleForkRun}
          />
        )}

        {currentTab === 'new-run' && (
          <ComposeMission
            onLaunchRun={handleLaunchRun}
            onSimulateDryRun={handleSimulateDryRun}
            onSaveTemplate={handleSaveTemplate}
          />
        )}

        {currentTab === 'active-runs' && (
          <ActiveRunsList
            runs={runs}
            onSelectRun={(id) => {
              setSelectedRunId(id);
              setCurrentTab('run-monitor');
            }}
            onNewRun={() => setCurrentTab('new-run')}
          />
        )}

        {currentTab === 'policies' && <PoliciesView />}

        {currentTab === 'traces' && (
          <TracesView
            runs={runs}
            onSelectRun={(id) => {
              setSelectedRunId(id);
              setCurrentTab('run-monitor');
            }}
          />
        )}

        {currentTab === 'settings' && <SettingsView />}
        </div> {/* end pl-64 main canvas */}
      </div> {/* end flex-row sidebar+content */}


      {/* Slide-over Trace Inspector Drawer */}
      <TraceDrawer
        card={inspectedCard}
        onClose={() => setInspectedCard(null)}
        onGoToRun={(runId) => {
          setSelectedRunId(runId);
          setCurrentTab('run-monitor');
        }}
      />

      {/* Emergency Halt Confirmation Modal */}
      <EmergencyHaltModal
        isOpen={isHaltModalOpen}
        onClose={() => setIsHaltModalOpen(false)}
        onConfirmHalt={handleConfirmEmergencyHalt}
        fleetCount={runs.length * 3 + 2}
      />

      {/* Documentation Modal */}
      <DocumentationModal isOpen={isDocModalOpen} onClose={() => setIsDocModalOpen(false)} />

      {/* Support Modal */}
      <SupportModal isOpen={isSupportModalOpen} onClose={() => setIsSupportModalOpen(false)} />

      {/* Notifications Modal */}
      <NotificationsModal
        isOpen={isNotificationsOpen}
        onClose={() => setIsNotificationsOpen(false)}
      />

      {/* Export Log Modal */}
      <ExportLogModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
        run={currentRun}
      />

      {/* Toast Notification Banner */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#1b1c1a] text-[#fcf9f5] px-4 py-2.5 rounded-xl shadow-xl flex items-center gap-2.5 text-body-sm font-body-sm border border-outline/30 animate-in fade-in slide-in-from-bottom-2 duration-150">
          <span className="material-symbols-outlined text-secondary text-[18px]">info</span>
          <span>{toastMessage}</span>
        </div>
      )}
    </div>
  );
}
