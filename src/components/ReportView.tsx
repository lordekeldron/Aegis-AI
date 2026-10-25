/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  FileText,
  Download,
  Copy,
  Printer,
  ShieldCheck,
  ShieldAlert,
  Calendar,
  Code2,
  CheckCircle2,
} from 'lucide-react';
import { ScanReport } from '../types/security';

interface ReportViewProps {
  scanReport: ScanReport | null;
}

export const ReportView: React.FC<ReportViewProps> = ({ scanReport }) => {
  const [copiedFormat, setCopiedFormat] = useState<string | null>(null);

  if (!scanReport) {
    return (
      <div className="bg-[#0E131F] border border-slate-800 rounded-xl p-12 text-center space-y-4">
        <div className="w-12 h-12 rounded-xl bg-slate-800/80 border border-slate-700 flex items-center justify-center mx-auto text-slate-400">
          <FileText className="w-6 h-6" />
        </div>
        <div className="space-y-1">
          <h3 className="text-base font-semibold text-white">Nenhum Relatório Gerado</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Realize uma varredura de código no <strong className="text-slate-300">Terminal de Diagnóstico</strong> para compilar o dossiê de auditoria técnica.
          </p>
        </div>
      </div>
    );
  }

  // Generate Markdown representation
  const generateMarkdownReport = () => {
    return `# Relatório de Auditoria de Cibersegurança - AegisCode AI
**Data:** ${new Date(scanReport.timestamp).toLocaleString('pt-BR')}
**Arquivo Analisado:** \`${scanReport.filename}\` (${scanReport.loc} linhas, ${scanReport.language})
**Pontuação Global de Segurança:** ${scanReport.securityScore}/100

## 1. Sumário Executivo
${scanReport.summary}

### Métricas de Severidade:
- **Críticas:** ${scanReport.criticalCount}
- **Altas:** ${scanReport.highCount}
- **Médias:** ${scanReport.mediumCount}
- **Baixas:** ${scanReport.lowCount}
- **Total Identificado:** ${scanReport.totalVulnerabilities}

## 2. Impacto em Conformidade
- **OWASP Top 10:** ${scanReport.complianceImpact?.owaspTop10}
- **PCI-DSS:** ${scanReport.complianceImpact?.pciDssImpact}
- **SOC 2:** ${scanReport.complianceImpact?.soc2Impact}

## 3. Vulnerabilidades e Planos de Remediação

${scanReport.vulnerabilities.map((v, i) => `
### ${i + 1}. [${v.severity}] ${v.title}
- **CWE:** ${v.cweId}
- **Pontuação CVSS v3.1:** ${v.cvssScore}
- **Linhas Afetadas:** ${v.lineStart} a ${v.lineEnd}
- **Categoria OWASP:** ${v.owaspCategory}

**Diagnóstico & Impacto:**
${v.explanation}

**Vetor de Ataque:**
\`${v.attackVector}\`

**Passos para Correção:**
${v.remediationSteps.map((s) => `- ${s}`).join('\n')}

**Patch Unificado (.diff):**
\`\`\`diff
${v.unifiedDiff}
\`\`\`
`).join('\n')}

---
*Gerado automaticamente pelo motor neural AegisCode AI v2.4.0.*
`;
  };

  // Generate SARIF 2.1.0 standard
  const generateSarifJson = () => {
    return JSON.stringify(
      {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'AegisCode-AI',
                version: '2.4.0',
                rules: scanReport.vulnerabilities.map((v) => ({
                  id: v.cweId.split(':')[0].trim(),
                  name: v.title,
                  shortDescription: { text: v.title },
                  fullDescription: { text: v.explanation },
                })),
              },
            },
            results: scanReport.vulnerabilities.map((v) => ({
              ruleId: v.cweId.split(':')[0].trim(),
              level: v.severity === 'CRITICAL' || v.severity === 'HIGH' ? 'error' : 'warning',
              message: { text: v.explanation },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: scanReport.filename },
                    region: { startLine: v.lineStart, endLine: v.lineEnd },
                  },
                },
              ],
            })),
          },
        ],
      },
      null,
      2
    );
  };

  const copyReport = (format: 'markdown' | 'sarif' | 'json') => {
    let content = '';
    if (format === 'markdown') content = generateMarkdownReport();
    else if (format === 'sarif') content = generateSarifJson();
    else content = JSON.stringify(scanReport, null, 2);

    navigator.clipboard.writeText(content);
    setCopiedFormat(format);
    setTimeout(() => setCopiedFormat(null), 2000);
  };

  const downloadReport = (format: 'md' | 'sarif' | 'json') => {
    let content = '';
    let mime = 'text/plain';
    let filename = `aegiscode_report_${Date.now()}.${format}`;

    if (format === 'md') {
      content = generateMarkdownReport();
      mime = 'text/markdown;charset=utf-8';
    } else if (format === 'sarif') {
      content = generateSarifJson();
      mime = 'application/json;charset=utf-8';
      filename = `aegiscode_audit.sarif`;
    } else {
      content = JSON.stringify(scanReport, null, 2);
      mime = 'application/json;charset=utf-8';
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      {/* Top action bar */}
      <div className="bg-[#0E131F] border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <FileText className="w-5 h-5 text-emerald-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">
              Dossiê Técnico & Relatório Executivo de Auditoria
            </h3>
            <span className="text-xs text-slate-400">
              Conformidade DevSecOps para equipes de engenharia e lideranças de segurança.
            </span>
          </div>
        </div>

        {/* Export buttons */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => copyReport('markdown')}
            className="px-3 py-1.5 text-xs text-slate-300 bg-slate-900 border border-slate-700 rounded-lg hover:bg-slate-800 transition-colors flex items-center gap-1.5"
          >
            <Copy className="w-3.5 h-3.5" />
            <span>{copiedFormat === 'markdown' ? 'Copiado!' : 'Copiar Markdown'}</span>
          </button>

          <button
            onClick={() => downloadReport('sarif')}
            className="px-3 py-1.5 text-xs text-slate-300 bg-slate-900 border border-slate-700 rounded-lg hover:bg-slate-800 transition-colors flex items-center gap-1.5"
            title="Padrão oficial para GitHub Security e GitLab SAST"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Baixar SARIF 2.1.0</span>
          </button>

          <button
            onClick={() => downloadReport('md')}
            className="px-3 py-1.5 text-xs text-slate-300 bg-slate-900 border border-slate-700 rounded-lg hover:bg-slate-800 transition-colors flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Baixar .MD</span>
          </button>

          <button
            onClick={handlePrint}
            className="px-3 py-1.5 text-xs text-slate-950 font-semibold bg-emerald-400 hover:bg-emerald-300 rounded-lg transition-colors flex items-center gap-1.5"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Imprimir / Salvar PDF</span>
          </button>
        </div>
      </div>

      {/* Printable Report Canvas */}
      <div className="bg-[#0E131F] border border-slate-800 rounded-xl p-8 space-y-8 print:bg-white print:text-black print:border-none print:p-0">
        {/* Report Header */}
        <div className="border-b border-slate-800 print:border-gray-300 pb-6 flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xl font-bold tracking-tight text-white print:text-black">
                AegisCode<span className="text-emerald-400 print:text-emerald-700">AI</span>
              </span>
              <span className="text-xs text-slate-500 font-mono">| Security Audit Report</span>
            </div>
            <h2 className="text-lg font-bold text-slate-100 print:text-black mt-2">
              Relatório de Auditoria de Segurança de Código Estático
            </h2>
          </div>

          <div className="text-right text-xs text-slate-400 print:text-gray-600 font-mono space-y-0.5">
            <div>
              ID: <span className="text-slate-200 print:text-black">{scanReport.id}</span>
            </div>
            <div>
              Data: {new Date(scanReport.timestamp).toLocaleString('pt-BR')}
            </div>
            <div>
              Alvo: <span className="text-slate-200 print:text-black">{scanReport.filename}</span>
            </div>
          </div>
        </div>

        {/* Score & Executive Overview */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="p-4 bg-[#121826] print:bg-gray-100 rounded-lg border border-slate-800 print:border-gray-200">
            <div className="text-xs text-slate-400 print:text-gray-600">Score de Segurança</div>
            <div
              className={`text-3xl font-extrabold font-mono mt-1 ${
                scanReport.securityScore >= 80
                  ? 'text-emerald-400 print:text-emerald-700'
                  : scanReport.securityScore >= 50
                  ? 'text-amber-400 print:text-amber-700'
                  : 'text-rose-400 print:text-rose-700'
              }`}
            >
              {scanReport.securityScore}/100
            </div>
          </div>

          <div className="p-4 bg-[#121826] print:bg-gray-100 rounded-lg border border-slate-800 print:border-gray-200">
            <div className="text-xs text-slate-400 print:text-gray-600">Total de Vulnerabilidades</div>
            <div className="text-3xl font-extrabold font-mono text-slate-200 print:text-black mt-1">
              {scanReport.totalVulnerabilities}
            </div>
            <div className="text-[11px] text-slate-500 print:text-gray-600 font-mono mt-1">
              {scanReport.criticalCount} Críticas · {scanReport.highCount} Altas
            </div>
          </div>

          <div className="p-4 bg-[#121826] print:bg-gray-100 rounded-lg border border-slate-800 print:border-gray-200">
            <div className="text-xs text-slate-400 print:text-gray-600">Volume de Código</div>
            <div className="text-3xl font-extrabold font-mono text-slate-200 print:text-black mt-1">
              {scanReport.loc}
            </div>
            <div className="text-[11px] text-slate-500 print:text-gray-600 font-mono mt-1">
              Linhas de código ({scanReport.language})
            </div>
          </div>
        </div>

        {/* Executive Summary Prose */}
        <div className="space-y-2">
          <h4 className="text-sm font-bold text-white print:text-black uppercase tracking-wider font-mono">
            1. Sumário Executivo
          </h4>
          <p className="text-xs text-slate-300 print:text-gray-800 leading-relaxed bg-[#121826] print:bg-gray-50 p-4 rounded-lg border border-slate-800 print:border-gray-200">
            {scanReport.summary}
          </p>
        </div>

        {/* Detailed Findings */}
        <div className="space-y-4">
          <h4 className="text-sm font-bold text-white print:text-black uppercase tracking-wider font-mono">
            2. Vulnerabilidades & Recomendações de Correção
          </h4>

          <div className="space-y-4">
            {scanReport.vulnerabilities.map((v, i) => (
              <div
                key={v.id}
                className="p-5 bg-[#121826] print:bg-gray-50 rounded-lg border border-slate-800 print:border-gray-300 space-y-3"
              >
                <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-slate-800 print:border-gray-200 pb-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                        v.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-300 print:bg-red-100 print:text-red-800'
                          : 'bg-amber-500/20 text-amber-300 print:bg-yellow-100 print:text-yellow-800'
                      }`}
                    >
                      {v.severity}
                    </span>
                    <span className="text-xs font-bold text-white print:text-black">
                      {i + 1}. {v.title}
                    </span>
                  </div>
                  <div className="text-xs font-mono text-slate-400 print:text-gray-600">
                    CVSS {v.cvssScore.toFixed(1)} · {v.cweId.split(':')[0]} · Linhas {v.lineStart}-{v.lineEnd}
                  </div>
                </div>

                <div className="text-xs text-slate-300 print:text-gray-800 space-y-1">
                  <div><strong>Descrição:</strong> {v.explanation}</div>
                  <div><strong>Vetor de Ataque:</strong> <code className="text-rose-300 print:text-red-700">{v.attackVector}</code></div>
                </div>

                {/* Diff */}
                <div className="space-y-1">
                  <span className="text-[11px] font-mono text-slate-400 print:text-gray-600">Patch Aplicado / Sugerido:</span>
                  <pre className="p-3 bg-[#080C14] print:bg-gray-100 rounded text-[11px] font-mono text-slate-200 print:text-black overflow-x-auto leading-4">
                    {v.unifiedDiff}
                  </pre>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
