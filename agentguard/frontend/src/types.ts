export type NavigationTab = 
  | 'inbox' 
  | 'active-runs' 
  | 'run-monitor' 
  | 'new-run' 
  | 'policies' 
  | 'traces' 
  | 'settings';

export interface ApprovalCard {
  id: string;
  agentId: string;
  actionType: 'cli.exec' | 'cloud.deploy' | 'fs.remove' | 'webhook.dispatch';
  confidence: number;
  timeAgo: string;
  title: string;
  reasoning: string;
  codeHeaderLeft: string;
  codeHeaderRight: string;
  codePayload: string;
  isCodeJson?: boolean;
  isDestructive?: boolean;
  status: 'pending' | 'approved' | 'rejected';
  runId?: string;
  traceId?: string;
}

export interface StepEvent {
  stepNumber: number;
  id: string;
  type: 'ASK_HUMAN' | 'ALLOW' | 'DENY';
  title: string;
  timeAgo: string;
  reasoning?: string;
  payloadCode?: string;
  payloadLanguage?: string;
  responsePreview?: string;
  metadata?: Record<string, string>;
  isTripwire?: boolean;
  tripwireRule?: string;
  tripwireMessage?: string;
}

export interface ActiveRunData {
  id: string;
  name: string;
  objective: string;
  objectiveDescription: string;
  status: 'PAUSED (AWAITING INPUT)' | 'RUNNING' | 'COMPLETED' | 'HALTED';
  agentId: string;
  startedTimeAgo: string;
  model: string;
  pipeline: string;
  environment: string;
  stepsTaken: number;
  maxSteps: number;
  computeCost: number;
  computeCap: number;
  tokensProcessed: number;
  runtimeFormatted: string;
  avgLatencyMs: number;
  latencyCeilingMs: number;
  interventionCount: number;
  activeInterventionStep?: number;
  steps: StepEvent[];
}

export interface PolicyRule {
  id: string;
  code: string;
  name: string;
  category: 'Security' | 'Network' | 'Filesystem' | 'Compute';
  description: string;
  status: 'Enforced' | 'Supervisory' | 'Audit-Only';
  tripsCount: number;
  lastTripped?: string;
}
