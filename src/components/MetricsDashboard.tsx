/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Search,
  Filter,
  CheckCircle2,
  Wand2,
  ExternalLink,
} from 'lucide-react';
import { ScanReport, Vulnerability, VulnerabilitySeverity } from '../types/security';

interface MetricsDashboardProps {
  scanReport: ScanReport | null;
  onApplyFix: (vuln: Vulnerability) => void;
  onSelectVuln: (vuln: Vulnerability) => void;
}

export const MetricsDashboard: React.FC<MetricsDashboardProps> = ({
  scanReport,
  onApplyFix,
  onSelectVuln,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  if (!scanReport) {
    return (
      <div className="bg-[#0E131F] border border-slate-800 rounded-xl p-8 text-center space-y-3">
        <div className="w-10 h-10 rounded-xl bg-slate-800/80 border border-slate-700 flex items-center justify-center mx-auto text-slate-400">
          <ShieldAlert className="w-5 h-5" />
        </div>
        <div className="space-y-1">
          <h3 className="text-sm font-semibold text-white">Nenhum Relatório de Métricas Disponível</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Execute uma varredura de código no <strong className="text-slate-300">Terminal de Diagnóstico</strong> para preencher o painel analítico com telemetria de vulnerabilidades, compliance e tempo de remediação.
          </p>
        </div>
        <div className="pt-2">
          <button
            onClick={() => onSelectVuln({} as any)}
            className="px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-emerald-400 rounded-lg hover:bg-emerald-300 transition-colors"
          >
            Abrir Terminal de Diagnóstico
          </button>
        </div>
      </div>
    );
  }

  // Calculate metrics
  const vulnerabilities = scanReport.vulnerabilities || [];
  const filteredVulns = vulnerabilities.filter((v) => {
    const matchesSearch =
      v.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      v.cweId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      v.explanation.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === 'ALL' || v.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const appliedCount = vulnerabilities.filter((v) => v.isApplied).length;
  const remediationRate = vulnerabilities.length > 0
    ? Math.round((appliedCount / vulnerabilities.length) * 100)
    : 100;

  // OWASP category distribution
  const owaspCounts: Record<string, number> = {};
  vulnerabilities.forEach((v) => {
    const cat = v.owaspCategory || 'Outros';
    owaspCounts[cat] = (owaspCounts[cat] || 0) + 1;
  });

  return (
    <div className="space-y-6">
      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Score Card */}
        <div className="bg-[#0E131F] border border-slate-800 rounded-xl p-5">
          <div className="text-xs text-slate-400 font-medium">Postura de Segurança Global</div>
          <div className="flex items-baseline gap-2 mt-2">
            <span
              className={`text-3xl font-extrabold font-mono tabular-nums ${
                scanReport.securityScore >= 80
                  ? 'text-emerald-400'
                  : scanReport.securityScore >= 50
                  ? 'text-amber-400'
                  : 'text-rose-400'
              }`}
            >
              {scanReport.securityScore}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ 100</span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            {scanReport.securityScore >= 80 ? (
              <span className="text-emerald-400 font-medium">Postura Firme · Baixo Risco</span>
            ) : scanReport.securityScore >= 50 ? (
              <span className="text-amber-400 font-medium">Atenção Requerida · Risco Médio</span>
            ) : (
              <span className="text-rose-400 font-medium">Risco Crítico · Intervenção Imediata</span>
            )}
          </div>
        </div>

        {/* Severity Count Card */}
        <div className="bg-[#0E131F] border border-slate-800 rounded-xl p-5">
          <div className="text-xs text-slate-400 font-medium">Severidade das Vulnerabilidades</div>
          <div className="flex items-center gap-3 mt-3">
            <div className="text-center">
              <div className="text-lg font-bold font-mono text-rose-400 tabular-nums">
                {scanReport.criticalCount}
              </div>
              <div className="text-[11px] text-slate-500">Crítica</div>
            </div>
            <span className="text-slate-800" aria-hidden="true">|</span>
            <div className="text-center">
              <div className="text-lg font-bold font-mono text-amber-400 tabular-nums">
                {scanReport.highCount}
              </div>
              <div className="text-[11px] text-slate-500">Alta</div>
            </div>
            <span className="text-slate-800" aria-hidden="true">|</span>
            <div className="text-center">
              <div className="text-lg font-bold font-mono text-blue-400 tabular-nums">
                {scanReport.mediumCount}
              </div>
              <div className="text-[11px] text-slate-500">Média</div>
            </div>
            <span className="text-slate-800" aria-hidden="true">|</span>
            <div className="text-center">
              <div className="text-lg font-bold font-mono text-slate-400 tabular-nums">
                {scanReport.lowCount}
              </div>
              <div className="text-[11px] text-slate-500">Baixa</div>
            </div>
          </div>
          <div className="mt-2 text-[11px] text-slate-500 font-mono">
            Total auditado: {scanReport.totalVulnerabilities} falhas
          </div>
        </div>

        {/* Remediation Rate */}
        <div className="bg-[#0E131F] border border-slate-800 rounded-xl p-5">
          <div className="text-xs text-slate-400 font-medium">Taxa de Remediação Automática</div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-3xl font-extrabold font-mono text-emerald-400 tabular-nums">
              {remediationRate}%
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400">
            {appliedCount} de {vulnerabilities.length} patches aplicados no código
          </div>
        </div>

        {/* File & Code Scope */}
        <div className="bg-[#0E131F] border border-slate-800 rounded-xl p-5">
          <div className="text-xs text-slate-400 font-medium">Escopo Analisado</div>
          <div className="mt-2 text-xs font-mono text-slate-200 truncate">
            {scanReport.filename}
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center gap-2">
            <span>{scanReport.loc} LOC</span>
            <span aria-hidden="true">·</span>
            <span className="uppercase font-mono">{scanReport.language}</span>
            <span aria-hidden="true">·</span>
            <span>{new Date(scanReport.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
          </div>
        </div>
      </div>

      {/* Middle Section: OWASP Breakdown & Compliance Posture */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* OWASP Category Breakdown (7 cols) */}
        <div className="lg:col-span-7 bg-[#0E131F] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-semibold text-white">Distribuição por Categoria OWASP</h4>
            <span className="text-xs text-slate-500 font-mono">Top 10 (2021)</span>
          </div>
          <div className="space-y-3">
            {Object.entries(owaspCounts).map(([cat, count]) => {
              const pct = Math.round((count / vulnerabilities.length) * 100);
              return (
                <div key={cat} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 font-medium truncate max-w-sm">{cat}</span>
                    <span className="text-slate-400 font-mono tabular-nums">
                      {count} ({pct}%)
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-emerald-500 rounded-full"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Compliance Posture Matrix (5 cols) */}
        <div className="lg:col-span-5 bg-[#0E131F] border border-slate-800 rounded-xl p-5 space-y-4">
          <h4 className="text-sm font-semibold text-white">Impacto em Conformidade & Auditoria</h4>
          <div className="space-y-3 text-xs">
            <div className="p-3 bg-[#121826] border border-slate-800 rounded-lg space-y-1">
              <div className="font-semibold text-slate-200">OWASP Top 10</div>
              <p className="text-slate-400">{scanReport.complianceImpact?.owaspTop10}</p>
            </div>
            <div className="p-3 bg-[#121826] border border-slate-800 rounded-lg space-y-1">
              <div className="font-semibold text-slate-200">PCI-DSS v4.0 (Req 6.5)</div>
              <p className="text-slate-400">{scanReport.complianceImpact?.pciDssImpact}</p>
            </div>
            <div className="p-3 bg-[#121826] border border-slate-800 rounded-lg space-y-1">
              <div className="font-semibold text-slate-200">SOC 2 Type II (CC6.1)</div>
              <p className="text-slate-400">{scanReport.complianceImpact?.soc2Impact}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Vulnerabilities Table & Feed */}
      <div className="bg-[#0E131F] border border-slate-800 rounded-xl overflow-hidden">
        {/* Table Filters Header */}
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <h4 className="text-sm font-semibold text-white">Vulnerabilidades Identificadas</h4>
            <span className="text-xs text-slate-500 font-mono">({filteredVulns.length})</span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Buscar por CWE, título ou termo..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg pl-8 pr-3 py-1.5 focus:outline-none focus:border-emerald-500 w-52 sm:w-64"
              />
            </div>

            {/* Severity Filter Tabs */}
            <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg text-xs">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2.5 py-1 rounded font-medium transition-colors ${
                    severityFilter === sev
                      ? 'bg-slate-800 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev === 'ALL' ? 'Todas' : sev}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Data Grid Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#121826] text-slate-400 border-b border-slate-800 font-mono">
              <tr>
                <th className="py-3 px-4">Severidade</th>
                <th className="py-3 px-4">CVSS</th>
                <th className="py-3 px-4">Vulnerabilidade / CWE</th>
                <th className="py-3 px-4">Linhas</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Ação</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {filteredVulns.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    Nenhuma vulnerabilidade encontrada para os filtros selecionados.
                  </td>
                </tr>
              ) : (
                filteredVulns.map((v) => (
                  <tr
                    key={v.id}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                    onClick={() => onSelectVuln(v)}
                  >
                    <td className="py-3 px-4">
                      <span
                        className={`font-mono px-2 py-0.5 rounded font-bold text-[10px] ${
                          v.severity === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : v.severity === 'HIGH'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                        }`}
                      >
                        {v.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono font-bold text-slate-200 tabular-nums">
                      {v.cvssScore.toFixed(1)}
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-medium text-slate-200">{v.title}</div>
                      <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                        {v.cweId}
                      </div>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 tabular-nums">
                      {v.lineStart === v.lineEnd ? `L${v.lineStart}` : `L${v.lineStart}-${v.lineEnd}`}
                    </td>
                    <td className="py-3 px-4">
                      {v.isApplied ? (
                        <span className="text-emerald-400 font-medium inline-flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Remediado</span>
                        </span>
                      ) : (
                        <span className="text-amber-400 font-medium">Pendente</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onApplyFix(v);
                        }}
                        className={`px-3 py-1 text-xs rounded transition-colors inline-flex items-center gap-1 ${
                          v.isApplied
                            ? 'text-slate-500 cursor-default'
                            : 'bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20 border border-emerald-500/30 font-medium'
                        }`}
                      >
                        <Wand2 className="w-3 h-3" />
                        <span>{v.isApplied ? 'Aplicado' : 'Auto-Fix'}</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
