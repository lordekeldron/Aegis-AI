/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export type VulnerabilitySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Vulnerability {
  id: string;
  title: string;
  severity: VulnerabilitySeverity;
  cvssScore: number;
  cweId: string;
  owaspCategory: string;
  lineStart: number;
  lineEnd: number;
  vulnerableSnippet: string;
  explanation: string;
  attackVector: string;
  remediationCode: string;
  remediationSteps: string[];
  unifiedDiff: string;
  relatedLogClue?: string;
  isApplied?: boolean;
}

export interface LogCorrelation {
  hasCorrelatedLogs: boolean;
  detectedExceptions: string[];
  crashLineNumber?: number;
  diagnosticInsight: string;
  exploitConfirmation: boolean;
}

export interface ComplianceImpact {
  owaspTop10: string;
  pciDssImpact: string;
  soc2Impact: string;
}

export interface ScanReport {
  id: string;
  timestamp: string;
  filename: string;
  language: string;
  loc: number;
  securityScore: number; // 0 to 100
  summary: string;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  vulnerabilities: Vulnerability[];
  logCorrelation?: LogCorrelation;
  complianceImpact: ComplianceImpact;
}

export interface CIPolicyConfig {
  failOnSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'NEVER';
  maxAllowedHigh: number;
  blockPullRequest: boolean;
  generateSarif: boolean;
  postPrComment: boolean;
}

export interface CISimulationResult {
  passed: boolean;
  exitCode: number;
  pipelineDurationMs: number;
  steps: {
    name: string;
    status: 'success' | 'failed' | 'skipped';
    output: string[];
    durationMs: number;
  }[];
  prCommentMarkdown: string;
  sarifPayload: object;
}
