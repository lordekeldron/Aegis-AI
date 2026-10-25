/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef } from 'react';
import {
  Play,
  UploadCloud,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Download,
  Wand2,
  ChevronRight,
  Terminal,
  RotateCcw,
  Sparkles,
  Shield,
  Trash2,
  Code2,
} from 'lucide-react';
import { ScanReport, Vulnerability } from '../types/security';
import { CODE_SAMPLES, SUPPORTED_LANGUAGES } from '../data/samples';

interface CodeScannerProps {
  code: string;
  setCode: (code: string) => void;
  language: string;
  setLanguage: (lang: string) => void;
  filename: string;
  setFilename: (name: string) => void;
  errorLogs: string;
  setErrorLogs: (logs: string) => void;
  scanReport: ScanReport | null;
  onScan: () => void;
  isScanning: boolean;
  onApplyFix: (vuln: Vulnerability) => void;
}

export const CodeScanner: React.FC<CodeScannerProps> = ({
  code,
  setCode,
  language,
  setLanguage,
  filename,
  setFilename,
  errorLogs,
  setErrorLogs,
  scanReport,
  onScan,
  isScanning,
  onApplyFix,
}) => {
  const [selectedVulnIndex, setSelectedVulnIndex] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<'diff' | 'remediation' | 'exploit'>('diff');
  const [mobileView, setMobileView] = useState<'editor' | 'inspector'>('editor');
  const [showLogsDrawer, setShowLogsDrawer] = useState<boolean>(Boolean(errorLogs));
  const [copyFeedback, setCopyFeedback] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const logFileInputRef = useRef<HTMLInputElement>(null);

  // File upload handler
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFilename(file.name);
    // Detect language from extension
    const ext = file.name.split('.').pop()?.toLowerCase();
    if (ext === 'py') setLanguage('python');
    else if (ext === 'ts' || ext === 'tsx') setLanguage('typescript');
    else if (ext === 'js' || ext === 'jsx') setLanguage('javascript');
    else if (ext === 'go') setLanguage('go');
    else if (ext === 'java') setLanguage('java');
    else if (ext === 'rs') setLanguage('rust');
    else if (ext === 'c' || ext === 'cpp' || ext === 'h') setLanguage('c');
    else if (ext === 'php') setLanguage('php');
    else if (ext === 'rb') setLanguage('ruby');
    else if (ext === 'cs') setLanguage('csharp');
    else if (file.name.toLowerCase().includes('dockerfile')) setLanguage('dockerfile');
    else if (ext === 'sql') setLanguage('sql');

    const reader = new FileReader();
    reader.onload = (event) => {
      if (typeof event.target?.result === 'string') {
        setCode(event.target.result);
      }
    };
    reader.readAsText(file);
  };

  // Log file upload handler
  const handleLogUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      if (typeof event.target?.result === 'string') {
        setErrorLogs(event.target.result);
        setShowLogsDrawer(true);
      }
    };
    reader.readAsText(file);
  };

  // Load sample code
  const handleLoadSample = (sampleId: string) => {
    const sample = CODE_SAMPLES.find((s) => s.id === sampleId);
    if (!sample) return;
    setCode(sample.code);
    setLanguage(sample.language);
    setFilename(sample.filename);
    setErrorLogs(sample.sampleErrorLogs);
    setShowLogsDrawer(Boolean(sample.sampleErrorLogs));
    setMobileView('editor');
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopyFeedback(label);
    setTimeout(() => setCopyFeedback(null), 2000);
  };

  const downloadRemediatedCode = () => {
    const blob = new Blob([code], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename || `codigo_remediado.${language}`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleClearCode = () => {
    setCode('');
    setFilename('');
    setErrorLogs('');
  };

  const currentVuln = scanReport?.vulnerabilities?.[selectedVulnIndex];
  const lines = code ? code.split('\n') : [''];
  const lineCount = code.trim() ? lines.length : 0;

  return (
    <div className="space-y-4">
      {/* Streamlined App Toolbar */}
      <div className="bg-[#101522] border border-slate-800/90 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3 shadow-sm">
        {/* Left: Language & Samples in a compact cluster */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Language selector */}
          <div className="flex items-center gap-1.5">
            <Code2 className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              className="bg-slate-900 border border-slate-700/80 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-emerald-500 font-mono"
            >
              {SUPPORTED_LANGUAGES.map((lang) => (
                <option key={lang.id} value={lang.id}>
                  {lang.label}
                </option>
              ))}
            </select>
          </div>

          <span className="text-slate-700 hidden sm:inline" aria-hidden="true">·</span>

          {/* Quick sample loader dropdown */}
          <select
            onChange={(e) => {
              if (e.target.value) handleLoadSample(e.target.value);
            }}
            value=""
            className="bg-slate-900 border border-slate-700/80 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-emerald-500"
          >
            <option value="" disabled>Carregar Exemplo...</option>
            {CODE_SAMPLES.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>

          {/* Error logs toggle */}
          <button
            onClick={() => setShowLogsDrawer(!showLogsDrawer)}
            className={`px-2.5 py-1.5 rounded-lg border transition-colors flex items-center gap-1.5 ${
              errorLogs.trim()
                ? 'bg-amber-500/10 border-amber-500/40 text-amber-300 font-medium'
                : 'bg-slate-900 border-slate-700/80 text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>{errorLogs.trim() ? 'Logs (+)' : 'Anexar Logs'}</span>
          </button>
        </div>

        {/* Right: Upload & Primary Scan CTA */}
        <div className="flex items-center gap-2">
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            className="hidden"
            accept=".py,.ts,.tsx,.js,.jsx,.go,.java,.rs,.c,.cpp,.h,.php,.rb,.cs,.sql,.yaml,.yml,Dockerfile,.txt"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            className="px-2.5 py-1.5 text-xs text-slate-300 bg-slate-900 border border-slate-700/80 rounded-lg hover:bg-slate-800 transition-colors flex items-center gap-1.5"
            title="Importar arquivo de código do computador"
          >
            <UploadCloud className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">Anexar Código</span>
            <span className="sm:hidden">Anexar</span>
          </button>

          <button
            onClick={() => {
              onScan();
              setMobileView('inspector');
            }}
            disabled={isScanning || !code.trim()}
            className={`px-4 py-1.5 text-xs font-semibold rounded-lg flex items-center gap-1.5 transition-all shadow-sm ${
              isScanning || !code.trim()
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold active:scale-[0.98]'
            }`}
          >
            {isScanning ? (
              <>
                <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                <span>Analisando...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Escanear Código</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Mobile Toggle Switcher (Visible only on mobile/tablet when scanReport exists) */}
      {scanReport && (
        <div className="lg:hidden flex items-center p-1 bg-slate-900 border border-slate-800 rounded-lg text-xs font-medium">
          <button
            onClick={() => setMobileView('editor')}
            className={`flex-1 py-1.5 text-center rounded-md transition-colors ${
              mobileView === 'editor'
                ? 'bg-slate-800 text-emerald-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Terminal ({lineCount}L)
          </button>
          <button
            onClick={() => setMobileView('inspector')}
            className={`flex-1 py-1.5 text-center rounded-md transition-colors flex items-center justify-center gap-1.5 ${
              mobileView === 'inspector'
                ? 'bg-slate-800 text-emerald-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>Vulnerabilidades</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-rose-500/20 text-rose-300 font-mono">
              {scanReport.totalVulnerabilities}
            </span>
          </button>
        </div>
      )}

      {/* Error Logs Drawer */}
      {showLogsDrawer && (
        <div className="bg-[#0D121F] border border-amber-500/30 rounded-xl p-3.5 space-y-2.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs text-amber-300 font-medium">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              <span>Logs de Erro & Rastreio de Stack Trace (Diagnóstico Avançado)</span>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="file"
                ref={logFileInputRef}
                onChange={handleLogUpload}
                className="hidden"
                accept=".log,.txt"
              />
              <button
                onClick={() => logFileInputRef.current?.click()}
                className="text-xs text-amber-400 hover:underline flex items-center gap-1"
              >
                <UploadCloud className="w-3 h-3" />
                <span>Upload .log</span>
              </button>
              {errorLogs.trim() && (
                <button
                  onClick={() => setErrorLogs('')}
                  className="text-xs text-slate-400 hover:text-slate-200"
                >
                  Limpar
                </button>
              )}
            </div>
          </div>
          <textarea
            value={errorLogs}
            onChange={(e) => setErrorLogs(e.target.value)}
            placeholder="Cole aqui rastros de pilha, logs do console, erros 500 ou alertas de segurança..."
            rows={3}
            className="w-full bg-[#070A12] border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-amber-200/90 focus:outline-none focus:border-amber-500/50"
          />
        </div>
      )}

      {/* Main Workspace Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
        {/* Terminal de Código (6 cols on desktop, responsive) */}
        <div
          className={`${
            scanReport ? 'lg:col-span-6' : 'lg:col-span-8'
          } ${mobileView === 'inspector' && scanReport ? 'hidden lg:block' : 'block'} bg-[#0D121F] border border-slate-800/90 rounded-xl overflow-hidden shadow-sm`}
        >
          {/* Terminal Header */}
          <div className="bg-[#121827] px-3.5 py-2 border-b border-slate-800 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shrink-0" />
              <Terminal className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span className="text-xs font-semibold text-slate-200 truncate">
                Terminal de Diagnóstico de Vulnerabilidades
              </span>
              {filename && (
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.2 rounded border border-emerald-500/20 truncate hidden sm:inline">
                  {filename}
                </span>
              )}
              <span className="text-[11px] text-slate-500 font-mono shrink-0">
                · {lineCount} {lineCount === 1 ? 'linha' : 'linhas'}
              </span>
            </div>

            {/* Actions in terminal title */}
            <div className="flex items-center gap-2 shrink-0">
              {code.trim() && (
                <>
                  <button
                    onClick={() => copyToClipboard(code, 'code')}
                    className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1"
                    title="Copiar código"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">{copyFeedback === 'code' ? 'Copiado!' : 'Copiar'}</span>
                  </button>
                  <button
                    onClick={downloadRemediatedCode}
                    className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1"
                    title="Baixar código"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={handleClearCode}
                    className="text-xs text-slate-400 hover:text-rose-400 flex items-center gap-1"
                    title="Limpar terminal"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">Limpar</span>
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Line numbered Code Textarea */}
          <div className="relative font-mono text-xs overflow-auto max-h-[560px] flex bg-[#080B14]">
            {/* Line numbers gutter */}
            <div className="py-2.5 px-2 bg-[#0A0E18] text-slate-600 select-none text-right font-mono min-w-[38px] border-r border-slate-800/80">
              {code.trim() ? (
                lines.map((_, i) => {
                  const lineNum = i + 1;
                  const isVulnerable =
                    currentVuln &&
                    lineNum >= currentVuln.lineStart &&
                    lineNum <= currentVuln.lineEnd;
                  return (
                    <div
                      key={i}
                      className={`leading-5 text-[11px] ${
                        isVulnerable
                          ? 'text-rose-400 font-bold bg-rose-500/20 px-0.5 rounded'
                          : ''
                      }`}
                    >
                      {lineNum}
                    </div>
                  );
                })
              ) : (
                [1, 2, 3, 4, 5, 6, 7, 8].map((n) => (
                  <div key={n} className="leading-5 text-[11px] text-slate-700">
                    {n}
                  </div>
                ))
              )}
            </div>

            {/* Code textarea */}
            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              spellCheck={false}
              className="w-full bg-transparent text-slate-200 p-2.5 leading-5 resize-none focus:outline-none min-h-[440px] font-mono whitespace-pre"
              placeholder={`// Terminal de Diagnóstico de Vulnerabilidades
// Cole ou digite seu código aqui para iniciar a análise de segurança...
// Suporta Python, JavaScript/TypeScript, Go, Java, Rust, C/C++, Dockerfile, etc.
// Ou selecione um caso em "Carregar Exemplo" acima para testar.`}
            />
          </div>
        </div>

        {/* Right Column: AI Security Inspector & Real-time Auto-Fix */}
        <div
          className={`${
            scanReport ? 'lg:col-span-6' : 'lg:col-span-4'
          } ${mobileView === 'editor' && scanReport ? 'hidden lg:block' : 'block'} space-y-4`}
        >
          {!scanReport && !isScanning ? (
            <div className="bg-[#0D121F] border border-slate-800/90 rounded-xl p-5 space-y-4">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                <h4 className="text-xs font-semibold text-white uppercase tracking-wider font-mono">
                  Guia Rápido de Diagnóstico
                </h4>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">
                O <strong>Terminal de Diagnóstico de Vulnerabilidades</strong> analisa código-fonte estático em tempo real, mapeia falhas conforme <strong>OWASP Top 10</strong> e sugere patches com diff estilo Git prontos para merge.
              </p>

              <div className="space-y-2 pt-1 border-t border-slate-800/80">
                <span className="text-[11px] font-medium text-slate-300">Testar casos reais de exploração:</span>
                <div className="flex flex-col gap-1.5">
                  <button
                    onClick={() => handleLoadSample('python-sqli-cmd')}
                    className="text-left p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-colors flex items-center justify-between"
                  >
                    <span>Python: SQL Injection & Command RCE</span>
                    <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                  </button>
                  <button
                    onClick={() => handleLoadSample('ts-ssrf-proto')}
                    className="text-left p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-colors flex items-center justify-between"
                  >
                    <span>TypeScript: SSRF & Prototype Pollution</span>
                    <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                  </button>
                  <button
                    onClick={() => handleLoadSample('go-path-traversal')}
                    className="text-left p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-colors flex items-center justify-between"
                  >
                    <span>Go: Directory Path Traversal</span>
                    <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                  </button>
                </div>
              </div>
            </div>
          ) : isScanning ? (
            <div className="bg-[#0D121F] border border-slate-800/90 rounded-xl p-8 text-center space-y-3">
              <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mx-auto text-emerald-400 animate-pulse">
                <RotateCcw className="w-5 h-5 animate-spin" />
              </div>
              <div className="space-y-1">
                <h3 className="text-xs font-semibold text-white">Analisando Código no Terminal</h3>
                <p className="text-[11px] text-slate-400 max-w-xs mx-auto">
                  Avaliando vetores de ataque, checando integridade de dados e gerando patches automáticos...
                </p>
              </div>
            </div>
          ) : scanReport ? (
            <div className="bg-[#0D121F] border border-slate-800/90 rounded-xl overflow-hidden shadow-sm space-y-3.5 p-3.5">
              {/* Scan summary banner */}
              <div className="flex flex-wrap items-center justify-between gap-2 pb-2.5 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400">Score:</span>
                  <span
                    className={`text-xs font-bold font-mono px-2 py-0.5 rounded ${
                      scanReport.securityScore >= 80
                        ? 'bg-emerald-500/20 text-emerald-300'
                        : scanReport.securityScore >= 50
                        ? 'bg-amber-500/20 text-amber-300'
                        : 'bg-rose-500/20 text-rose-300'
                    }`}
                  >
                    {scanReport.securityScore}/100
                  </span>
                  <span className="text-[11px] text-slate-500 font-mono">
                    · {scanReport.totalVulnerabilities} falhas
                  </span>
                </div>

                <div className="flex items-center gap-1.5 text-[10px] font-mono">
                  {scanReport.criticalCount > 0 && (
                    <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                      {scanReport.criticalCount} Crítica(s)
                    </span>
                  )}
                  {scanReport.highCount > 0 && (
                    <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                      {scanReport.highCount} Alta(s)
                    </span>
                  )}
                  {scanReport.mediumCount > 0 && (
                    <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
                      {scanReport.mediumCount} Média(s)
                    </span>
                  )}
                </div>
              </div>

              {/* Vulnerabilities Selector List */}
              <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                {scanReport.vulnerabilities.map((v, idx) => (
                  <button
                    key={v.id}
                    onClick={() => setSelectedVulnIndex(idx)}
                    className={`w-full text-left p-2 rounded-lg border transition-all flex items-center justify-between gap-2 ${
                      selectedVulnIndex === idx
                        ? 'bg-slate-800 border-emerald-500/50'
                        : 'bg-[#111624] border-slate-800/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span
                        className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold shrink-0 ${
                          v.severity === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : v.severity === 'HIGH'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                        }`}
                      >
                        {v.severity}
                      </span>
                      <div className="truncate">
                        <div className="text-xs font-medium text-slate-200 truncate">
                          {v.title}
                        </div>
                        <div className="text-[10px] text-slate-400 font-mono">
                          {v.cweId.split(':')[0]} · L{v.lineStart}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
                      {v.isApplied && (
                        <span className="text-[9px] text-emerald-400 font-medium flex items-center gap-0.5">
                          <CheckCircle2 className="w-3 h-3" />
                          <span className="hidden sm:inline">Corrigido</span>
                        </span>
                      )}
                      <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                    </div>
                  </button>
                ))}
              </div>

              {/* Active Vulnerability Detail Card */}
              {currentVuln && (
                <div className="bg-[#111624] border border-slate-800/90 rounded-lg p-3 space-y-3">
                  {/* Header info */}
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-1.5 text-xs font-mono">
                        <span className="font-bold text-rose-400">
                          CVSS {currentVuln.cvssScore.toFixed(1)}
                        </span>
                        <span className="text-slate-500">·</span>
                        <span className="text-slate-300">
                          {currentVuln.cweId}
                        </span>
                      </div>
                      <h4 className="text-xs font-semibold text-white mt-0.5">
                        {currentVuln.title}
                      </h4>
                    </div>

                    {/* Auto-Fix button */}
                    <button
                      onClick={() => onApplyFix(currentVuln)}
                      className={`px-2.5 py-1 text-xs font-semibold rounded-lg flex items-center gap-1 transition-colors ${
                        currentVuln.isApplied
                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                          : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold active:scale-[0.98]'
                      }`}
                    >
                      <Wand2 className="w-3.5 h-3.5" />
                      <span>{currentVuln.isApplied ? 'Aplicado no Terminal' : 'Aplicar Correção no Código'}</span>
                    </button>
                  </div>

                  {/* Log clue if correlated */}
                  {currentVuln.relatedLogClue && (
                    <div className="p-2 rounded bg-amber-500/10 border border-amber-500/30 text-[11px] text-amber-200 font-mono flex items-start gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <strong className="text-amber-300">Evidência em Log: </strong>
                        {currentVuln.relatedLogClue}
                      </div>
                    </div>
                  )}

                  {/* Tabs: Diff vs Remediation vs Exploit */}
                  <div className="flex items-center gap-1 border-b border-slate-800 pb-1 text-xs">
                    <button
                      onClick={() => setActiveTab('diff')}
                      className={`px-2 py-0.5 font-medium transition-colors ${
                        activeTab === 'diff'
                          ? 'text-emerald-400 border-b-2 border-emerald-400 font-semibold'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      Diff Git
                    </button>
                    <button
                      onClick={() => setActiveTab('remediation')}
                      className={`px-2 py-0.5 font-medium transition-colors ${
                        activeTab === 'remediation'
                          ? 'text-emerald-400 border-b-2 border-emerald-400 font-semibold'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      Passos
                    </button>
                    <button
                      onClick={() => setActiveTab('exploit')}
                      className={`px-2 py-0.5 font-medium transition-colors ${
                        activeTab === 'exploit'
                          ? 'text-emerald-400 border-b-2 border-emerald-400 font-semibold'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      Vetor de Ataque
                    </button>
                  </div>

                  {/* Tab 1: Unified Git Diff */}
                  {activeTab === 'diff' && (
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-[11px] text-slate-400">
                        <span className="font-mono">Patch de Remediação Automática:</span>
                        <button
                          onClick={() => copyToClipboard(currentVuln.unifiedDiff, 'diff')}
                          className="hover:text-slate-200 flex items-center gap-1"
                        >
                          <Copy className="w-3 h-3" />
                          <span>{copyFeedback === 'diff' ? 'Copiado!' : 'Copiar .patch'}</span>
                        </button>
                      </div>
                      <div className="bg-[#070A12] border border-slate-800 rounded-lg p-2.5 font-mono text-[11px] overflow-x-auto leading-4.5 max-h-48">
                        {currentVuln.unifiedDiff.split('\n').map((line, i) => {
                          const isAdd = line.startsWith('+') && !line.startsWith('+++');
                          const isDel = line.startsWith('-') && !line.startsWith('---');
                          const isHeader = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++');
                          return (
                            <div
                              key={i}
                              className={`${
                                isAdd
                                  ? 'text-emerald-400 bg-emerald-500/10'
                                  : isDel
                                  ? 'text-rose-400 bg-rose-500/10'
                                  : isHeader
                                  ? 'text-blue-400'
                                  : 'text-slate-300'
                              }`}
                            >
                              {line}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Tab 2: Remediation Steps */}
                  {activeTab === 'remediation' && (
                    <div className="space-y-2 text-xs">
                      <p className="text-slate-300 text-[11px]">{currentVuln.explanation}</p>
                      <div className="space-y-1">
                        <strong className="text-slate-200 text-[11px]">Recomendações técnicas:</strong>
                        <ul className="list-disc pl-4 space-y-0.5 text-slate-400 text-[11px]">
                          {currentVuln.remediationSteps.map((step, i) => (
                            <li key={i}>{step}</li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <strong className="text-slate-200 font-mono text-[11px]">Código Remediado:</strong>
                        <pre className="mt-1 p-2 rounded bg-[#070A12] border border-slate-800 text-emerald-300 font-mono text-[11px] overflow-x-auto">
                          {currentVuln.remediationCode}
                        </pre>
                      </div>
                    </div>
                  )}

                  {/* Tab 3: Exploit Vector */}
                  {activeTab === 'exploit' && (
                    <div className="space-y-2 text-xs">
                      <div>
                        <strong className="text-slate-200 text-[11px]">Vetor de Exploração:</strong>
                        <p className="text-slate-300 mt-1 font-mono bg-[#070A12] p-2 rounded border border-slate-800 text-rose-300/90 text-[11px]">
                          {currentVuln.attackVector}
                        </p>
                      </div>
                      <div>
                        <strong className="text-slate-200 text-[11px]">Snippet Vulnerável:</strong>
                        <pre className="mt-1 p-2 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 font-mono text-[11px]">
                          {currentVuln.vulnerableSnippet}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
};
