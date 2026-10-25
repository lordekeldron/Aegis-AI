/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  MessageSquare,
  X,
  Send,
  RotateCcw,
  Bot,
  User,
  Sparkles,
  ArrowRight,
  Copy,
  Check,
  Code2,
  Terminal,
  Minimize2,
  Maximize2,
} from 'lucide-react';
import { ScanReport } from '../types/security';

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

interface SecurityChatProps {
  currentCode: string;
  language: string;
  scanReport: ScanReport | null;
  errorLogs: string;
  onApplyCodeToTerminal?: (code: string) => void;
}

export const SecurityChat: React.FC<SecurityChatProps> = ({
  currentCode,
  language,
  scanReport,
  errorLogs,
  onApplyCodeToTerminal,
}) => {
  const [isOpen, setIsOpen] = useState<boolean>(false);
  const [isMinimized, setIsMinimized] = useState<boolean>(false);
  const [inputMessage, setInputMessage] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content:
        'Olá! Sou o **AegisCode Copilot**. Você pode me dar feedbacks sobre as vulnerabilidades detectadas, esclarecer dúvidas de código, pedir para ajustar um patch ou debater se algum apontamento é falso positivo.',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen && !isMinimized) {
      scrollToBottom();
    }
  }, [messages, isOpen, isMinimized]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen && !isMinimized) {
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [isOpen, isMinimized]);

  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputMessage).trim();
    if (!text || isLoading) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputMessage('');
    setIsLoading(true);

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: [...messages, userMsg].map((m) => ({
            role: m.role,
            content: m.content,
          })),
          currentCode,
          language,
          scanReport,
          errorLogs,
        }),
      });

      const data = await response.json();

      const assistantMsg: ChatMessage = {
        id: `assistant-${Date.now()}`,
        role: 'assistant',
        content: data.reply || 'Feedback recebido. Estou à disposição para mais dúvidas.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      const errorMsg: ChatMessage = {
        id: `err-${Date.now()}`,
        role: 'assistant',
        content:
          'Não consegui me conectar no momento. Pode reenviar sua mensagem ou verificar se a rede está ativa?',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const copyCode = (codeText: string, id: string) => {
    navigator.clipboard.writeText(codeText);
    setCopiedCodeId(id);
    setTimeout(() => setCopiedCodeId(null), 2000);
  };

  // Helper to render markdown-like text and code snippets
  const renderMessageContent = (content: string, msgId: string) => {
    const parts = content.split(/(```[\s\S]*?```)/g);

    return (
      <div className="space-y-2 text-xs leading-relaxed">
        {parts.map((part, index) => {
          if (part.startsWith('```') && part.endsWith('```')) {
            const lines = part.slice(3, -3).trim().split('\n');
            const lang = lines[0].match(/^[a-zA-Z0-9_-]+$/) ? lines[0] : '';
            const codeBody = lang ? lines.slice(1).join('\n') : lines.join('\n');
            const blockId = `${msgId}-code-${index}`;

            return (
              <div
                key={index}
                className="my-2 rounded-lg bg-[#070A12] border border-slate-800 overflow-hidden font-mono"
              >
                <div className="bg-[#111724] px-2.5 py-1 text-[10px] text-slate-400 border-b border-slate-800 flex items-center justify-between">
                  <span>{lang || 'código'}</span>
                  <div className="flex items-center gap-2">
                    {onApplyCodeToTerminal && (
                      <button
                        onClick={() => onApplyCodeToTerminal(codeBody)}
                        className="text-emerald-400 hover:text-emerald-300 transition-colors flex items-center gap-1 font-sans"
                        title="Inserir este código diretamente no Terminal de Diagnóstico"
                      >
                        <Terminal className="w-3 h-3" />
                        <span>Aplicar ao Terminal</span>
                      </button>
                    )}
                    <button
                      onClick={() => copyCode(codeBody, blockId)}
                      className="text-slate-400 hover:text-slate-200 transition-colors flex items-center gap-1"
                    >
                      {copiedCodeId === blockId ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      <span>{copiedCodeId === blockId ? 'Copiado' : 'Copiar'}</span>
                    </button>
                  </div>
                </div>
                <pre className="p-2.5 text-[11px] text-slate-200 overflow-x-auto leading-4.5 whitespace-pre">
                  {codeBody}
                </pre>
              </div>
            );
          }

          // Format bold text **text** and bullet lines
          const paragraphs = part.split('\n\n');
          return paragraphs.map((p, pIdx) => {
            const formatted = p.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
            return (
              <p
                key={`${index}-${pIdx}`}
                className="whitespace-pre-line text-slate-200"
                dangerouslySetInnerHTML={{ __html: formatted }}
              />
            );
          });
        })}
      </div>
    );
  };

  // Quick feedback suggestion pills
  const quickPrompts = [
    'É um falso positivo?',
    'Refinar correção para variáveis de ambiente',
    'Como testar este exploit com segurança?',
    'Explicar impacto no OWASP Top 10',
  ];

  return (
    <>
      {/* Floating Toggle Button */}
      {!isOpen && (
        <button
          onClick={() => {
            setIsOpen(true);
            setIsMinimized(false);
          }}
          className="fixed bottom-16 md:bottom-6 right-4 md:right-6 z-40 px-3.5 py-2.5 bg-slate-900 border border-emerald-500/40 hover:border-emerald-500 text-slate-100 rounded-full shadow-2xl hover:shadow-emerald-500/10 transition-all flex items-center gap-2 text-xs font-semibold group cursor-pointer active:scale-95"
          title="Abrir Chat com IA para dar feedbacks em tempo real"
        >
          <div className="w-6 h-6 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 group-hover:scale-110 transition-transform">
            <Sparkles className="w-3.5 h-3.5" />
          </div>
          <span className="text-slate-200">Chat com IA · Feedbacks</span>
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
        </button>
      )}

      {/* Chat Window Panel */}
      {isOpen && (
        <div
          className={`fixed z-50 transition-all duration-200 shadow-2xl border border-slate-800 bg-[#0B0F17]/95 backdrop-blur-md rounded-2xl flex flex-col overflow-hidden ${
            isMinimized
              ? 'bottom-16 md:bottom-6 right-4 md:right-6 w-72 h-14'
              : 'bottom-16 md:bottom-6 right-3 md:right-6 w-[94vw] sm:w-[420px] max-w-full h-[520px] max-h-[82vh]'
          }`}
        >
          {/* Header */}
          <div className="px-3.5 py-2.5 bg-[#101522] border-b border-slate-800 flex items-center justify-between gap-2 shrink-0">
            <div className="flex items-center gap-2 min-w-0">
              <div className="w-6 h-6 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
                <Bot className="w-3.5 h-3.5" />
              </div>
              <div className="truncate">
                <div className="text-xs font-bold text-slate-100 truncate flex items-center gap-1.5">
                  <span>AegisCode Copilot</span>
                  <span className="text-[10px] text-emerald-400 font-mono font-normal">v2.4</span>
                </div>
                <div className="text-[10px] text-slate-400 truncate">
                  Feedbacks de segurança em tempo real
                </div>
              </div>
            </div>

            <div className="flex items-center gap-1 shrink-0">
              <button
                onClick={() => setIsMinimized(!isMinimized)}
                className="p-1 text-slate-400 hover:text-slate-200 rounded transition-colors"
                title={isMinimized ? 'Expandir' : 'Minimizar'}
              >
                {isMinimized ? <Maximize2 className="w-3.5 h-3.5" /> : <Minimize2 className="w-3.5 h-3.5" />}
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1 text-slate-400 hover:text-slate-200 rounded transition-colors"
                title="Fechar chat"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Body & Messages */}
          {!isMinimized && (
            <>
              <div className="flex-1 overflow-y-auto p-3.5 space-y-3">
                {messages.map((msg) => (
                  <div
                    key={msg.id}
                    className={`flex items-start gap-2 ${
                      msg.role === 'user' ? 'justify-end' : 'justify-start'
                    }`}
                  >
                    {msg.role === 'assistant' && (
                      <div className="w-6 h-6 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0 mt-0.5">
                        <Bot className="w-3.5 h-3.5" />
                      </div>
                    )}

                    <div
                      className={`max-w-[85%] rounded-xl p-3 ${
                        msg.role === 'user'
                          ? 'bg-emerald-500/15 border border-emerald-500/30 text-slate-100 rounded-tr-sm'
                          : 'bg-[#121826] border border-slate-800 text-slate-200 rounded-tl-sm'
                      }`}
                    >
                      {renderMessageContent(msg.content, msg.id)}
                      <div className="mt-1 text-[9px] text-slate-500 text-right font-mono">
                        {msg.timestamp}
                      </div>
                    </div>

                    {msg.role === 'user' && (
                      <div className="w-6 h-6 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 shrink-0 mt-0.5">
                        <User className="w-3.5 h-3.5" />
                      </div>
                    )}
                  </div>
                ))}

                {isLoading && (
                  <div className="flex items-start gap-2">
                    <div className="w-6 h-6 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
                      <Bot className="w-3.5 h-3.5" />
                    </div>
                    <div className="p-2.5 rounded-xl bg-[#121826] border border-slate-800 text-slate-400 text-xs flex items-center gap-2">
                      <RotateCcw className="w-3 h-3 animate-spin text-emerald-400" />
                      <span>Processando seu feedback...</span>
                    </div>
                  </div>
                )}

                <div ref={messagesEndRef} />
              </div>

              {/* Quick suggestion prompt chips */}
              <div className="px-3 py-1.5 bg-[#0D121E] border-t border-slate-800/80 flex items-center gap-1.5 overflow-x-auto whitespace-nowrap text-[11px] no-scrollbar">
                {quickPrompts.map((prompt, i) => (
                  <button
                    key={i}
                    onClick={() => handleSendMessage(prompt)}
                    disabled={isLoading}
                    className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 transition-colors text-[10px] shrink-0 disabled:opacity-50"
                  >
                    {prompt}
                  </button>
                ))}
              </div>

              {/* Input Box Footer */}
              <div className="p-2.5 bg-[#101522] border-t border-slate-800">
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    handleSendMessage();
                  }}
                  className="flex items-end gap-1.5"
                >
                  <textarea
                    ref={inputRef}
                    value={inputMessage}
                    onChange={(e) => setInputMessage(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Dê seu feedback sobre o código ou vulnerabilidades..."
                    rows={1}
                    className="flex-1 bg-[#070A12] border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500 resize-none max-h-24 leading-5"
                  />
                  <button
                    type="submit"
                    disabled={isLoading || !inputMessage.trim()}
                    className={`p-2 rounded-lg transition-colors shrink-0 ${
                      isLoading || !inputMessage.trim()
                        ? 'bg-slate-800 text-slate-600 cursor-not-allowed'
                        : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold'
                    }`}
                    title="Enviar mensagem (Enter)"
                  >
                    <Send className="w-4 h-4" />
                  </button>
                </form>
              </div>
            </>
          )}
        </div>
      )}
    </>
  );
};
