/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { Shield, Terminal, BarChart3, FileText, GitBranch, AlertTriangle, Plus } from 'lucide-react';

export type ActiveTab = 'scanner' | 'metrics' | 'logs' | 'cicd' | 'report';

interface TopNavProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  onNewScan: () => void;
  hasScanData: boolean;
  criticalCount: number;
}

export const TopNav: React.FC<TopNavProps> = ({
  activeTab,
  onTabChange,
  onNewScan,
  hasScanData,
  criticalCount,
}) => {
  return (
    <>
      {/* Top Header - Streamlined for Desktop & Mobile */}
      <header className="sticky top-0 z-40 bg-[#0A0E17]/95 backdrop-blur-md border-b border-slate-800/80">
        <div className="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between gap-4 h-14">
            {/* Zone 1: Single element wordmark */}
            <div className="flex items-center gap-2 whitespace-nowrap shrink-0">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                <Shield className="w-4 h-4" />
              </div>
              <span className="text-base font-bold tracking-tight text-white">
                AegisCode<span className="text-emerald-400">AI</span>
              </span>
            </div>

            {/* Zone 2: Desktop Navigation Links */}
            <nav className="hidden md:flex items-center gap-6 text-xs font-medium">
              <button
                onClick={() => onTabChange('scanner')}
                className={`flex items-center gap-1.5 py-1 transition-colors whitespace-nowrap shrink-0 ${
                  activeTab === 'scanner'
                    ? 'text-emerald-400 font-semibold border-b-2 border-emerald-400'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Scanner & Patch</span>
              </button>

              <button
                onClick={() => onTabChange('metrics')}
                className={`flex items-center gap-1.5 py-1 transition-colors whitespace-nowrap shrink-0 ${
                  activeTab === 'metrics'
                    ? 'text-emerald-400 font-semibold border-b-2 border-emerald-400'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <BarChart3 className="w-3.5 h-3.5" />
                <span>Métricas</span>
                {hasScanData && criticalCount > 0 && (
                  <span className="text-[10px] font-mono text-rose-400 bg-rose-500/10 px-1 rounded">
                    {criticalCount}
                  </span>
                )}
              </button>

              <button
                onClick={() => onTabChange('logs')}
                className={`flex items-center gap-1.5 py-1 transition-colors whitespace-nowrap shrink-0 ${
                  activeTab === 'logs'
                    ? 'text-emerald-400 font-semibold border-b-2 border-emerald-400'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Diagnóstico de Logs</span>
              </button>

              <button
                onClick={() => onTabChange('cicd')}
                className={`flex items-center gap-1.5 py-1 transition-colors whitespace-nowrap shrink-0 ${
                  activeTab === 'cicd'
                    ? 'text-emerald-400 font-semibold border-b-2 border-emerald-400'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <GitBranch className="w-3.5 h-3.5" />
                <span>CI/CD</span>
              </button>

              <button
                onClick={() => onTabChange('report')}
                className={`flex items-center gap-1.5 py-1 transition-colors whitespace-nowrap shrink-0 ${
                  activeTab === 'report'
                    ? 'text-emerald-400 font-semibold border-b-2 border-emerald-400'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Relatórios</span>
              </button>
            </nav>

            {/* Zone 3: 1 primary action */}
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={onNewScan}
                className="px-3 py-1.5 text-xs font-semibold text-slate-950 bg-emerald-400 rounded-lg hover:bg-emerald-300 transition-colors shadow-sm whitespace-nowrap shrink-0 flex items-center gap-1.5"
                title="Limpar e iniciar nova análise"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Novo Scan</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Mobile App Bottom Navigation Bar */}
      <nav className="md:hidden fixed bottom-0 left-0 right-0 z-40 bg-[#0B0F17]/95 backdrop-blur-lg border-t border-slate-800 px-2 py-1.5 flex items-center justify-around shadow-2xl">
        <button
          onClick={() => onTabChange('scanner')}
          className={`flex flex-col items-center gap-0.5 py-1 px-2.5 rounded-lg transition-colors ${
            activeTab === 'scanner' ? 'text-emerald-400 bg-emerald-500/10' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="w-4 h-4" />
          <span className="text-[10px] font-medium">Terminal</span>
        </button>

        <button
          onClick={() => onTabChange('metrics')}
          className={`flex flex-col items-center gap-0.5 py-1 px-2.5 rounded-lg transition-colors relative ${
            activeTab === 'metrics' ? 'text-emerald-400 bg-emerald-500/10' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <BarChart3 className="w-4 h-4" />
          <span className="text-[10px] font-medium">Métricas</span>
          {hasScanData && criticalCount > 0 && (
            <span className="absolute top-0.5 right-1.5 w-2 h-2 rounded-full bg-rose-500" />
          )}
        </button>

        <button
          onClick={() => onTabChange('logs')}
          className={`flex flex-col items-center gap-0.5 py-1 px-2.5 rounded-lg transition-colors ${
            activeTab === 'logs' ? 'text-emerald-400 bg-emerald-500/10' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <AlertTriangle className="w-4 h-4" />
          <span className="text-[10px] font-medium">Logs</span>
        </button>

        <button
          onClick={() => onTabChange('cicd')}
          className={`flex flex-col items-center gap-0.5 py-1 px-2.5 rounded-lg transition-colors ${
            activeTab === 'cicd' ? 'text-emerald-400 bg-emerald-500/10' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitBranch className="w-4 h-4" />
          <span className="text-[10px] font-medium">CI/CD</span>
        </button>

        <button
          onClick={() => onTabChange('report')}
          className={`flex flex-col items-center gap-0.5 py-1 px-2.5 rounded-lg transition-colors ${
            activeTab === 'report' ? 'text-emerald-400 bg-emerald-500/10' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileText className="w-4 h-4" />
          <span className="text-[10px] font-medium">Relatório</span>
        </button>
      </nav>
    </>
  );
};
