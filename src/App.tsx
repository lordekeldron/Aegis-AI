/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { TopNav, ActiveTab } from './components/TopNav';
import { CodeScanner } from './components/CodeScanner';
import { MetricsDashboard } from './components/MetricsDashboard';
import { LogDiagnostics } from './components/LogDiagnostics';
import { CiCdIntegration } from './components/CiCdIntegration';
import { ReportView } from './components/ReportView';
import { SecurityChat } from './components/SecurityChat';
import { ScanReport, Vulnerability } from './types/security';
import { CODE_SAMPLES } from './data/samples';
import { CheckCircle2, AlertCircle } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('scanner');
  const [code, setCode] = useState<string>('');
  const [language, setLanguage] = useState<string>('python');
  const [filename, setFilename] = useState<string>('');
  const [errorLogs, setErrorLogs] = useState<string>('');
  const [scanReport, setScanReport] = useState<ScanReport | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 3500);
  };

  // Perform Security Scan
  const handleScan = async () => {
    if (!code.trim()) return;
    setIsScanning(true);

    try {
      const response = await fetch('/api/security/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code,
          filename,
          language,
          errorLogs,
        }),
      });

      if (!response.ok) {
        throw new Error(`Falha no servidor (${response.status})`);
      }

      const report: ScanReport = await response.json();
      setScanReport(report);
      showToast(
        `Varredura concluída! ${report.totalVulnerabilities} vulnerabilidade(s) detectada(s).`
      );
    } catch (err: any) {
      console.error('Scan error:', err);
      showToast(`Erro na análise: ${err.message || 'Tente novamente'}`);
    } finally {
      setIsScanning(false);
    }
  };

  // Real-Time In-Place Code Remediation
  const handleApplyFix = (vuln: Vulnerability) => {
    if (vuln.isApplied) return;

    let updatedCode = code;

    // Check if vulnerableSnippet exists in code
    if (vuln.vulnerableSnippet && code.includes(vuln.vulnerableSnippet)) {
      updatedCode = code.replace(vuln.vulnerableSnippet, vuln.remediationCode);
    } else {
      // Line range replacement fallback
      const lines = code.split('\n');
      const start = Math.max(0, vuln.lineStart - 1);
      const end = Math.min(lines.length, vuln.lineEnd);

      const before = lines.slice(0, start);
      const after = lines.slice(end);
      updatedCode = [...before, vuln.remediationCode, ...after].join('\n');
    }

    setCode(updatedCode);

    // Update scan report state to mark vulnerability as fixed
    if (scanReport) {
      const updatedVulns = scanReport.vulnerabilities.map((v) =>
        v.id === vuln.id ? { ...v, isApplied: true } : v
      );

      const remainingActive = updatedVulns.filter((v) => !v.isApplied);
      const newCritical = remainingActive.filter((v) => v.severity === 'CRITICAL').length;
      const newHigh = remainingActive.filter((v) => v.severity === 'HIGH').length;
      const newMedium = remainingActive.filter((v) => v.severity === 'MEDIUM').length;
      const newLow = remainingActive.filter((v) => v.severity === 'LOW').length;

      const newScore = Math.min(
        100,
        Math.max(10, 100 - (newCritical * 25 + newHigh * 12 + newMedium * 6 + newLow * 2))
      );

      setScanReport({
        ...scanReport,
        vulnerabilities: updatedVulns,
        criticalCount: newCritical,
        highCount: newHigh,
        mediumCount: newMedium,
        lowCount: newLow,
        securityScore: newScore,
      });
    }

    showToast(`Correção automática aplicada com sucesso para "${vuln.title}"!`);
  };

  // Jump to vulnerability in scanner
  const handleSelectVuln = (_vuln: Vulnerability) => {
    setActiveTab('scanner');
  };

  const handleNewScan = () => {
    setCode('');
    setLanguage('python');
    setFilename('');
    setErrorLogs('');
    setScanReport(null);
    setActiveTab('scanner');
    showToast('Terminal limpo. Pronto para nova análise.');
  };

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col selection:bg-emerald-500/30 selection:text-emerald-200">
      {/* Top Bar Navigation */}
      <TopNav
        activeTab={activeTab}
        onTabChange={setActiveTab}
        onNewScan={handleNewScan}
        hasScanData={Boolean(scanReport)}
        criticalCount={scanReport?.criticalCount || 0}
      />

      {/* Toast Alert */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-slate-900 border border-emerald-500/40 text-slate-100 px-4 py-3 rounded-xl shadow-xl flex items-center gap-2.5 text-xs font-medium">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-3 sm:px-6 lg:px-8 py-4 pb-20 md:pb-6">
        {activeTab === 'scanner' && (
          <CodeScanner
            code={code}
            setCode={setCode}
            language={language}
            setLanguage={setLanguage}
            filename={filename}
            setFilename={setFilename}
            errorLogs={errorLogs}
            setErrorLogs={setErrorLogs}
            scanReport={scanReport}
            onScan={handleScan}
            isScanning={isScanning}
            onApplyFix={handleApplyFix}
          />
        )}

        {activeTab === 'metrics' && (
          <MetricsDashboard
            scanReport={scanReport}
            onApplyFix={handleApplyFix}
            onSelectVuln={handleSelectVuln}
          />
        )}

        {activeTab === 'logs' && (
          <LogDiagnostics
            errorLogs={errorLogs}
            setErrorLogs={setErrorLogs}
            scanReport={scanReport}
            onScanWithLogs={handleScan}
            isScanning={isScanning}
          />
        )}

        {activeTab === 'cicd' && (
          <CiCdIntegration scanReport={scanReport} />
        )}

        {activeTab === 'report' && (
          <ReportView scanReport={scanReport} />
        )}
      </main>

      {/* Quiet Footer */}
      <footer className="border-t border-slate-900 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-400">AegisCode AI</span>
            <span aria-hidden="true">·</span>
            <span>Segurança Contínua em Tempo Real</span>
          </div>
          <div className="flex items-center gap-4 text-[11px] text-slate-500 font-mono">
            <span>OWASP Top 10</span>
            <span>CWE Matrix</span>
            <span>SARIF 2.1.0</span>
            <span>GitHub Actions</span>
          </div>
        </div>
      </footer>

      {/* Real-time AI Security Feedback Chat */}
      <SecurityChat
        currentCode={code}
        language={language}
        scanReport={scanReport}
        errorLogs={errorLogs}
        onApplyCodeToTerminal={(newCode) => {
          setCode(newCode);
          showToast('Código sugerido pela IA aplicado ao Terminal de Diagnóstico!');
        }}
      />
    </div>
  );
}
