/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useRef } from 'react';
import {
  AlertTriangle,
  UploadCloud,
  FileText,
  Activity,
  CheckCircle2,
  XCircle,
  Sparkles,
  ArrowRight,
  Code2,
} from 'lucide-react';
import { ScanReport } from '../types/security';

interface LogDiagnosticsProps {
  errorLogs: string;
  setErrorLogs: (logs: string) => void;
  scanReport: ScanReport | null;
  onScanWithLogs: () => void;
  isScanning: boolean;
}

export const LogDiagnostics: React.FC<LogDiagnosticsProps> = ({
  errorLogs,
  setErrorLogs,
  scanReport,
  onScanWithLogs,
  isScanning,
}) => {
  const logFileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      if (typeof event.target?.result === 'string') {
        setErrorLogs(event.target.result);
      }
    };
    reader.readAsText(file);
  };

  const loadExampleLogs = (type: 'sqli' | 'ssrf' | 'xxe') => {
    if (type === 'sqli') {
      setErrorLogs(`[2026-10-24 18:22:10] CRITICAL [werkzeug:189] - Exception on /api/login [POST]
Traceback (most recent call last):
  File "/usr/local/lib/python3.11/site-packages/flask/app.py", line 2529, in wsgi_app
    response = self.full_dispatch_request()
  File "auth_service.py", line 21, in user_login
    cursor.execute(query)
sqlite3.OperationalError: unrecognized token: "admin'--" syntax error near line 1
[2026-10-24 18:22:45] WARNING [security_audit] - Suspicious process spawn detected:
Command: 'ping -c 1 127.0.0.1; cat /etc/passwd' executed by UID 1001 (flask-worker)`);
    } else if (type === 'ssrf') {
      setErrorLogs(`[2026-10-24 14:15:02] ERROR [WebhookService] Request to metadata endpoint initiated:
Target: http://169.254.169.254/latest/meta-data/iam/security-credentials/
AxiosError: connect ECONNREFUSED 169.254.169.254:80
  at AxiosError.from (/app/node_modules/axios/lib/core/AxiosError.js:89:14)
  at /app/webhook_processor.ts:28:34
[2026-10-24 14:18:19] WARN [NodeRuntime] Object prototype mutation detected.
Payload contained '__proto__.isAdmin: true' triggering privilege escalation.`);
    } else {
      setErrorLogs(`2026-10-24 09:12:33.402 ERROR 1 --- [nio-8080-exec-4] c.a.s.c.PaymentBatchController :
java.io.InvalidClassException: org.apache.commons.collections.functors.InvokerTransformer;
local class incompatible: stream classdesc serialVersionUID = 47829124018
  at com.aegis.security.controller.PaymentBatchController.restoreSession(PaymentBatchController.java:18)
[ATTACK TRIGGERED] Gadget chain execution intercepted in Sandbox!`);
    }
  };

  const correlation = scanReport?.logCorrelation;

  return (
    <div className="space-y-6">
      {/* Intro Header */}
      <div className="bg-[#0E131F] border border-slate-800 rounded-xl p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-1">
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-amber-400" />
              <span>Diagnóstico de Cibersegurança Baseado em Logs de Erro</span>
            </h3>
            <p className="text-xs text-slate-400 max-w-2xl">
              Conecte logs de produção, rastros de pilha (stack traces) de crashes ou relatórios de auditoria ao código-fonte. A IA cruza eventos de tempo de execução com o código estático para provar se uma vulnerabilidade está sob ataque ativo.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="file"
              ref={logFileInputRef}
              onChange={handleFileUpload}
              className="hidden"
              accept=".log,.txt"
            />
            <button
              onClick={() => logFileInputRef.current?.click()}
              className="px-3 py-1.5 text-xs text-slate-300 bg-slate-900 border border-slate-700 rounded-lg hover:bg-slate-800 transition-colors flex items-center gap-1.5"
            >
              <UploadCloud className="w-3.5 h-3.5" />
              <span>Anexar Arquivo .log</span>
            </button>
          </div>
        </div>

        {/* Quick sample logs picker */}
        <div className="mt-4 pt-4 border-t border-slate-800/80 flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-400">Carregar Log de Exemplo:</span>
          <button
            onClick={() => loadExampleLogs('sqli')}
            className="text-xs px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded border border-slate-700 transition-colors font-mono"
          >
            Crash SQLi + RCE (Python)
          </button>
          <button
            onClick={() => loadExampleLogs('ssrf')}
            className="text-xs px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded border border-slate-700 transition-colors font-mono"
          >
            Bloqueio SSRF Metadata (Node.js)
          </button>
          <button
            onClick={() => loadExampleLogs('xxe')}
            className="text-xs px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded border border-slate-700 transition-colors font-mono"
          >
            Gadget Chain Deserialization (Java)
          </button>
        </div>
      </div>

      {/* Editor & Diagnostic Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Log Input (6 cols) */}
        <div className="lg:col-span-6 bg-[#0E131F] border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="bg-[#141A29] px-4 py-2.5 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-amber-400" />
              <span className="text-xs font-mono text-slate-200">application_crash.log</span>
            </div>
            {errorLogs && (
              <button
                onClick={() => setErrorLogs('')}
                className="text-xs text-slate-400 hover:text-slate-200"
              >
                Limpar
              </button>
            )}
          </div>
          <textarea
            value={errorLogs}
            onChange={(e) => setErrorLogs(e.target.value)}
            rows={18}
            placeholder="Cole aqui o stack trace ou rastro de exceção gerado pela aplicação..."
            className="w-full bg-[#080C14] text-amber-200/90 font-mono text-xs p-4 leading-5 resize-none focus:outline-none"
          />
          <div className="p-3 bg-[#111724] border-t border-slate-800 flex justify-end">
            <button
              onClick={onScanWithLogs}
              disabled={isScanning || !errorLogs.trim()}
              className={`px-4 py-2 text-xs font-semibold rounded-lg flex items-center gap-2 transition-colors ${
                isScanning || !errorLogs.trim()
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Executar Diagnóstico Cruzado com IA</span>
            </button>
          </div>
        </div>

        {/* Right Column: Cross-Correlation Result (6 cols) */}
        <div className="lg:col-span-6 space-y-4">
          <div className="bg-[#0E131F] border border-slate-800 rounded-xl p-5 space-y-4">
            <h4 className="text-sm font-semibold text-white">Resultado da Correlação Código ↔ Logs</h4>

            {correlation ? (
              <div className="space-y-4">
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-start gap-3">
                  <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="text-xs font-semibold text-rose-300">
                      Exploração Ativa Confirmada em Runtime
                    </div>
                    <p className="text-xs text-slate-300 mt-1">
                      {correlation.diagnosticInsight}
                    </p>
                  </div>
                </div>

                <div className="space-y-2">
                  <span className="text-xs font-medium text-slate-400">Assinaturas e Exceções Extraídas:</span>
                  <div className="flex flex-wrap gap-2">
                    {correlation.detectedExceptions.map((exc, i) => (
                      <span
                        key={i}
                        className="px-2.5 py-1 bg-slate-900 border border-slate-700 text-slate-300 font-mono text-xs rounded"
                      >
                        {exc}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="p-3 bg-[#121826] border border-slate-800 rounded-lg space-y-2">
                  <div className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                    <Code2 className="w-4 h-4 text-emerald-400" />
                    <span>Nó Vulnerável no Código-Fonte</span>
                  </div>
                  <p className="text-xs text-slate-400">
                    O rastro de pilha apontou falha na execução próxima à{' '}
                    <span className="text-emerald-400 font-mono font-bold">
                      Linha {correlation.crashLineNumber || '18-22'}
                    </span>. A vulnerabilidade estática foi validada com status de alta criticidade.
                  </p>
                </div>
              </div>
            ) : (
              <div className="py-12 text-center space-y-2 text-xs text-slate-400">
                <FileText className="w-8 h-8 mx-auto text-slate-600" />
                <p>Nenhum diagnóstico cruzado processado ainda.</p>
                <p className="text-slate-500 max-w-xs mx-auto">
                  Forneça logs de erro à esquerda e clique em "Executar Diagnóstico Cruzado com IA".
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
