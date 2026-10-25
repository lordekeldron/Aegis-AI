/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  GitBranch,
  Play,
  Copy,
  Download,
  CheckCircle2,
  XCircle,
  Terminal,
  ShieldAlert,
  ShieldCheck,
  Settings,
  RotateCcw,
  ExternalLink,
} from 'lucide-react';
import { CIPolicyConfig, CISimulationResult, ScanReport } from '../types/security';

interface CiCdIntegrationProps {
  scanReport: ScanReport | null;
}

export const CiCdIntegration: React.FC<CiCdIntegrationProps> = ({ scanReport }) => {
  const [provider, setProvider] = useState<'github' | 'gitlab'>('github');
  const [policy, setPolicy] = useState<CIPolicyConfig>({
    failOnSeverity: 'HIGH',
    maxAllowedHigh: 0,
    blockPullRequest: true,
    generateSarif: true,
    postPrComment: true,
  });
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [simulationResult, setSimulationResult] = useState<CISimulationResult | null>(null);
  const [copiedType, setCopiedType] = useState<string | null>(null);

  // GitHub Actions workflow configuration YAML
  const githubWorkflowYaml = `name: "AegisCode AI Security Scan"

on:
  push:
    branches: [ "main", "develop" ]
  pull_request:
    branches: [ "main" ]
  schedule:
    - cron: '0 2 * * 1' # Execucao semanal toda segunda-feira

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  security-audit:
    name: "SAST & Real-Time Remediation"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run AegisCode AI SAST Scanner
        id: aegis_scan
        uses: aegiscode-ai/action-scan@v2
        with:
          fail_on: "${policy.failOnSeverity}"
          max_high_allowed: "${policy.maxAllowedHigh}"
          sarif_output: "aegiscode-results.sarif"
          token: \${{ secrets.AEGISCODE_API_KEY }}

      - name: Upload SARIF to GitHub Security Tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: aegiscode-results.sarif
          category: "aegiscode-ai-sast"

      - name: Post PR Security Review Comment
        if: github.event_name == 'pull_request' && failure()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: \`🛡️ **AegisCode AI:** Falha na politica de seguranca. Verifique o relatorio na aba Security.\`
            })
`;

  // GitLab CI pipeline configuration YAML
  const gitlabCiYaml = `stages:
  - test
  - security
  - deploy

include:
  - template: Security/SAST.gitlab-ci.yml

aegiscode_sast:
  stage: security
  image: aegiscode/security-cli:latest
  variables:
    FAIL_ON_SEVERITY: "${policy.failOnSeverity}"
    MAX_HIGH_ALLOWED: "${policy.maxAllowedHigh}"
  script:
    - aegiscode scan --path . --output gl-sast-report.json --format gitlab-sast
    - aegiscode evaluate-policy --fail-on $FAIL_ON_SEVERITY --max-high $MAX_HIGH_ALLOWED
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
`;

  const copyToClipboard = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  const downloadYaml = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/yaml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Run simulated CI pipeline check
  const handleRunSimulation = async () => {
    if (!scanReport) return;
    setIsSimulating(true);

    try {
      const response = await fetch('/api/ci/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanReport,
          policy,
          provider,
        }),
      });
      const data = await response.json();
      setSimulationResult(data);
    } catch (err) {
      console.error('Simulation failed:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Overview */}
      <div className="bg-[#0E131F] border border-slate-800 rounded-xl p-6">
        <div className="space-y-1">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <GitBranch className="w-5 h-5 text-emerald-400" />
            <span>Automação DevSecOps & Integração CI/CD Contínua</span>
          </h3>
          <p className="text-xs text-slate-400 max-w-2xl">
            Adicione a segurança como porta de qualidade (Quality Gate) automatizada no fluxo de entrega contínua. Bloqueie pull requests vulneráveis e envie relatórios no padrão SARIF 2.1.0 para o GitHub ou GitLab.
          </p>
        </div>
      </div>

      {/* Provider Selector & Policy Config */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Pipeline Configurator & YAML Code (7 cols) */}
        <div className="lg:col-span-7 bg-[#0E131F] border border-slate-800 rounded-xl overflow-hidden shadow-sm space-y-4 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
            {/* Provider Tabs */}
            <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg text-xs">
              <button
                onClick={() => setProvider('github')}
                className={`px-3 py-1.5 rounded font-medium transition-colors ${
                  provider === 'github'
                    ? 'bg-slate-800 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                GitHub Actions (.yml)
              </button>
              <button
                onClick={() => setProvider('gitlab')}
                className={`px-3 py-1.5 rounded font-medium transition-colors ${
                  provider === 'gitlab'
                    ? 'bg-slate-800 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                GitLab CI (.gitlab-ci.yml)
              </button>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() =>
                  copyToClipboard(
                    provider === 'github' ? githubWorkflowYaml : gitlabCiYaml,
                    'yaml'
                  )
                }
                className="text-xs text-slate-300 bg-slate-900 border border-slate-700 px-2.5 py-1.5 rounded-lg hover:bg-slate-800 transition-colors flex items-center gap-1"
              >
                <Copy className="w-3.5 h-3.5" />
                <span>{copiedType === 'yaml' ? 'Copiado!' : 'Copiar YAML'}</span>
              </button>
              <button
                onClick={() =>
                  downloadYaml(
                    provider === 'github' ? githubWorkflowYaml : gitlabCiYaml,
                    provider === 'github' ? 'aegiscode-scan.yml' : '.gitlab-ci.yml'
                  )
                }
                className="text-xs text-slate-300 bg-slate-900 border border-slate-700 px-2.5 py-1.5 rounded-lg hover:bg-slate-800 transition-colors flex items-center gap-1"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Baixar</span>
              </button>
            </div>
          </div>

          {/* Policy Toggles */}
          <div className="bg-[#121826] border border-slate-800 rounded-lg p-3.5 space-y-3 text-xs">
            <div className="font-semibold text-slate-200 flex items-center gap-1.5">
              <Settings className="w-3.5 h-3.5 text-emerald-400" />
              <span>Regras de Bloqueio da Política (Security Gate)</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-slate-400 block mb-1">Interromper pipeline se encontrar:</label>
                <select
                  value={policy.failOnSeverity}
                  onChange={(e) =>
                    setPolicy({
                      ...policy,
                      failOnSeverity: e.target.value as any,
                    })
                  }
                  className="w-full bg-slate-900 border border-slate-700 text-slate-200 rounded px-2.5 py-1.5 font-mono"
                >
                  <option value="CRITICAL">Apenas Críticas (CRITICAL)</option>
                  <option value="HIGH">Críticas ou Altas (HIGH)</option>
                  <option value="MEDIUM">Médias ou superiores (MEDIUM)</option>
                  <option value="NEVER">Nunca interromper (Apenas auditar)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Máximo de falhas Altas toleradas:</label>
                <input
                  type="number"
                  min="0"
                  max="10"
                  value={policy.maxAllowedHigh}
                  onChange={(e) =>
                    setPolicy({
                      ...policy,
                      maxAllowedHigh: parseInt(e.target.value, 10) || 0,
                    })
                  }
                  className="w-full bg-slate-900 border border-slate-700 text-slate-200 rounded px-2.5 py-1.5 font-mono"
                />
              </div>
            </div>
          </div>

          {/* YAML Viewer */}
          <div className="space-y-1">
            <div className="text-[11px] font-mono text-slate-400">
              {provider === 'github' ? '.github/workflows/security-scan.yml' : '.gitlab-ci.yml'}
            </div>
            <pre className="p-3 bg-[#080C14] border border-slate-800 rounded-lg font-mono text-xs text-slate-300 leading-5 overflow-x-auto max-h-72">
              {provider === 'github' ? githubWorkflowYaml : gitlabCiYaml}
            </pre>
          </div>
        </div>

        {/* Right: Live Interactive CI/CD Simulator (5 cols) */}
        <div className="lg:col-span-5 bg-[#0E131F] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-semibold text-white flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span>Simulador de Runner CI/CD</span>
            </h4>

            <button
              onClick={handleRunSimulation}
              disabled={isSimulating || !scanReport}
              className={`px-3 py-1.5 text-xs font-semibold rounded-lg flex items-center gap-1.5 transition-colors ${
                isSimulating || !scanReport
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold'
              }`}
            >
              {isSimulating ? (
                <>
                  <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                  <span>Executando...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Simular Execução</span>
                </>
              )}
            </button>
          </div>

          {!scanReport ? (
            <div className="py-8 text-center text-xs text-slate-500 space-y-1">
              <ShieldAlert className="w-6 h-6 mx-auto text-slate-600" />
              <p>Execute um scan de código antes de testar a simulação do pipeline.</p>
            </div>
          ) : !simulationResult ? (
            <div className="p-4 bg-[#121826] border border-slate-800 rounded-lg text-xs text-slate-400 space-y-2">
              <p>
                Clique em <strong className="text-emerald-400">"Simular Execução"</strong> para visualizar como o pipeline do GitHub Actions ou GitLab CI se comportará com o código atual.
              </p>
              <div className="text-[11px] text-slate-500">
                · Simula o log de terminal do runner em tempo real.<br />
                · Avalia se o Pull Request seria aprovado ou bloqueado.<br />
                · Gera o comentário do bot no PR e payload SARIF 2.1.0.
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Pipeline Status Banner */}
              <div
                className={`p-3 rounded-lg border flex items-center justify-between ${
                  simulationResult.passed
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                    : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                }`}
              >
                <div className="flex items-center gap-2">
                  {simulationResult.passed ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <XCircle className="w-5 h-5 text-rose-400" />
                  )}
                  <div>
                    <div className="text-xs font-bold">
                      {simulationResult.passed
                        ? 'Pipeline Aprovado (Pass)'
                        : 'Pipeline Bloqueado (Security Gate Failure)'}
                    </div>
                    <div className="text-[10px] text-slate-400 font-mono">
                      Exit code: {simulationResult.exitCode} · Tempo: {simulationResult.pipelineDurationMs}ms
                    </div>
                  </div>
                </div>
              </div>

              {/* Runner Execution Steps */}
              <div className="space-y-2">
                <div className="text-xs font-medium text-slate-300">Etapas do Runner:</div>
                <div className="space-y-1.5 font-mono text-[11px]">
                  {simulationResult.steps.map((step, idx) => (
                    <div
                      key={idx}
                      className="p-2 bg-[#080C14] border border-slate-800 rounded space-y-1"
                    >
                      <div className="flex items-center justify-between text-slate-300">
                        <span className="flex items-center gap-1.5">
                          {step.status === 'success' ? (
                            <span className="text-emerald-400">✓</span>
                          ) : (
                            <span className="text-rose-400">✗</span>
                          )}
                          <span className="font-semibold">{step.name}</span>
                        </span>
                        <span className="text-slate-500 tabular-nums">{step.durationMs}ms</span>
                      </div>
                      <div className="pl-4 text-slate-400 space-y-0.5">
                        {step.output.map((out, oi) => (
                          <div key={oi}>{out}</div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* PR Bot Comment Preview */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span className="font-medium text-slate-300">Comentário Automático no Pull Request:</span>
                  <button
                    onClick={() =>
                      copyToClipboard(simulationResult.prCommentMarkdown, 'comment')
                    }
                    className="text-[11px] text-slate-400 hover:text-slate-200"
                  >
                    {copiedType === 'comment' ? 'Copiado!' : 'Copiar Markdown'}
                  </button>
                </div>
                <div className="p-3 bg-[#080C14] border border-slate-800 rounded-lg text-xs text-slate-300 max-h-44 overflow-y-auto leading-5 font-mono whitespace-pre-wrap">
                  {simulationResult.prCommentMarkdown}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
