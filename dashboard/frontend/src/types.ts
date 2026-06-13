// Mirrors the dashboard API (dashboard/server/schemas.py) and the nested
// ScanResult.to_dict() blocks the detail view renders.

export interface ScanSummary {
  id: number;
  run_id: string | null;
  run_label: string | null;
  source: string;
  filename: string;
  file_hash: string | null;
  language: string | null;
  triage_classification: string | null;
  final_verdict: string | null;
  risk_score: number | null;
  risk_level: string | null;
  intent: string | null;
  dast_attempted: boolean;
  n_findings: number;
  n_confirmed: number;
  remediation_confidence: string | null;
  total_cost_usd: number | null;
  total_duration_ms: number | null;
  created_at: string;
}

export interface ScanDetail extends ScanSummary {
  raw: RawScanResult;
}

export interface ScansPage {
  items: ScanSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface CountItem {
  key: string;
  count: number;
}

export interface TimeBucket {
  date: string;
  count: number;
  cost: number;
}

export interface Stats {
  total_scans: number;
  files_at_risk: number;
  confirmed_exploitable: number;
  auto_remediated_high: number;
  total_cost_usd: number;
  by_verdict: CountItem[];
  by_risk: CountItem[];
  by_severity: CountItem[];
  by_remediation_confidence: CountItem[];
  top_vuln_types: CountItem[];
  over_time: TimeBucket[];
}

export interface RunSummary {
  run_id: string;
  run_label: string | null;
  n_files: number;
  n_findings: number;
  n_confirmed: number;
  worst_verdict: string | null;
  total_cost_usd: number;
  created_at: string;
}

// ── Nested raw ScanResult blocks (the per-file flow) ──────────────────

export interface Vulnerability {
  type?: string;
  severity?: string;
  line?: number;
  code?: string;
  explanation?: string;
  fix?: string;
  cwe?: string;
  confidence?: number;
  data_flow_trace?: string;
  proof_of_concept?: string;
  intent_check?: string;
}

export interface PerFindingValidation {
  finding_id?: string;
  cwe?: string;
  type?: string;
  severity?: string;
  line?: number | null;
  status?: string; // CONFIRMED | REJECTED | BLOCKED | UNREACHED | NOT_TESTED
  confidence?: number | null;
  rejection_reason?: string | null;
  not_tested_reason?: string | null;
  proof_of_concept?: string | null;
  runtime_evidence?: string | null;
}

export interface Variant {
  description?: string;
  payload?: string;
  result?: string; // blocked | FIRED
  stdout?: string;
}

export interface Verification {
  confidence?: string; // HIGH | MEDIUM | LOW | FAILED
  severity?: string;
  functional_ok?: boolean | null;
  variants_total?: number;
  variants_fired?: number;
  variants?: Variant[];
  notes?: string[];
  n_sandbox_calls?: number;
}

export interface PerFindingFix {
  finding_ref?: string;
  change_description?: string;
}

export interface PerFindingRemediation {
  finding_ref?: string;
  hypothesis_id?: string;
  original_status?: string;
  post_patch_status?: string; // NEUTRALIZED | STILL_EXPLOITABLE | UNVERIFIABLE
  post_patch_verdict?: string;
  confidence?: string | null;
}

export interface PhaseC {
  attempted?: boolean;
  patched_source?: string | null;
  fix_summary?: string;
  per_finding_fixes?: PerFindingFix[];
  per_finding?: PerFindingRemediation[];
  post_patch_verdict?: string;
  n_neutralized?: number;
  n_still_exploitable?: number;
  n_unverifiable?: number;
  verification?: Verification | null;
  skipped_reason?: string | null;
  error?: string | null;
  elapsed_s?: number;
}

export interface ModelCall {
  stage?: string;
  model?: string;
  input_tokens?: number;
  output_tokens?: number;
  cost_usd?: number;
  duration_ms?: number;
  uncertainty?: number;
}

export interface RawScanResult {
  filename?: string;
  language?: string | null;
  triage_classification?: string;
  triage_reason?: string;
  final_verdict?: string;
  risk_score?: number;
  risk_level?: string;
  intent?: string;
  vulnerabilities?: Vulnerability[];
  attack_chains?: Array<{ name?: string; steps?: string[] }>;
  behavioral_profile?: Record<string, unknown>;
  dast_attempted?: boolean;
  per_finding_validation?: PerFindingValidation[];
  dast_iterations?: unknown[];
  phase_c?: PhaseC | null;
  scan_path?: string[];
  model_calls?: ModelCall[];
  total_cost_usd?: number;
  total_duration_ms?: number;
  status?: number;
  error?: string | null;
  [key: string]: unknown;
}
