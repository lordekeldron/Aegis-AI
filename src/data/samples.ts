/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface CodeSample {
  id: string;
  name: string;
  language: string;
  filename: string;
  code: string;
  sampleErrorLogs: string;
  description: string;
}

export const CODE_SAMPLES: CodeSample[] = [
  {
    id: 'python-sqli-cmd',
    name: 'Python (Flask API - SQLi & Command Injection)',
    language: 'python',
    filename: 'auth_service.py',
    description: 'Vulnerabilidades críticas: Injeção de SQL via f-strings brutas e execução arbitrária de comandos no sistema operacional.',
    code: `import os
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = "/var/data/users.db"
SECRET_KEY = "sk_live_998341908234_prod_admin_secret"  # Hardcoded API Secret

@app.route("/api/login", methods=["POST"])
def user_login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # VULNERABILITY 1: SQL Injection (CWE-89)
    # Concatenação insegura de string na query SQL
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT id, role, email FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()

    if not user:
        return jsonify({"error": "Credenciais invalidas"}), 401

    return jsonify({"status": "autenticado", "role": user[1]})

@app.route("/api/diagnostics/ping", methods=["GET"])
def run_ping():
    host = request.args.get("host", "127.0.0.1")

    # VULNERABILITY 2: Command Injection (CWE-78)
    # Entrada de host passada diretamente para os.popen sem sanitização
    command = f"ping -c 1 {host}"
    output = os.popen(command).read()

    return jsonify({"output": output})
`,
    sampleErrorLogs: `[2026-10-24 18:22:10] CRITICAL [werkzeug:189] - Exception on /api/login [POST]
Traceback (most recent call last):
  File "/usr/local/lib/python3.11/site-packages/flask/app.py", line 2529, in wsgi_app
    response = self.full_dispatch_request()
  File "auth_service.py", line 21, in user_login
    cursor.execute(query)
sqlite3.OperationalError: unrecognized token: "admin'--" syntax error near line 1
[2026-10-24 18:22:45] WARNING [security_audit] - Suspicious process spawn detected:
Command: 'ping -c 1 127.0.0.1; cat /etc/passwd' executed by UID 1001 (flask-worker)
`
  },
  {
    id: 'ts-ssrf-proto',
    name: 'TypeScript / Node.js (SSRF & Prototype Pollution)',
    language: 'typescript',
    filename: 'webhook_processor.ts',
    description: 'Vulnerabilidades de alta severidade: SSRF (Server-Side Request Forgery) e manipulação insegura de protótipos de objetos.',
    code: `import express, { Request, Response } from 'express';
import axios from 'axios';

const app = express();
app.use(express.json());

// VULNERABILITY 1: Insecure Object Merge leading to Prototype Pollution (CWE-1321)
function deepMerge(target: any, source: any): any {
  for (const key of Object.keys(source)) {
    if (source[key] instanceof Object && key in target) {
      Object.assign(source[key], deepMerge(target[key], source[key]));
    }
    // Falta checagem de __proto__, constructor ou prototype
    target[key] = source[key];
  }
  return target;
}

// VULNERABILITY 2: Server-Side Request Forgery (SSRF) (CWE-918)
app.post('/api/fetch-webhook', async (req: Request, res: Response) => {
  const { targetUrl, customHeaders } = req.body;

  if (!targetUrl) {
    return res.status(400).json({ error: 'URL obrigatoria' });
  }

  // Faz requisição HTTP para qualquer IP ou domínio fornecido pelo cliente
  // Inclusive http://169.254.169.254/latest/meta-data/ (AWS credentials)
  try {
    const response = await axios.get(targetUrl, {
      headers: customHeaders || {},
      timeout: 3000
    });
    return res.json({ status: 'ok', data: response.data });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/config/update', (req: Request, res: Response) => {
  const systemConfig: Record<string, any> = { env: 'production', debug: false };
  deepMerge(systemConfig, req.body);
  res.json({ updated: true, config: systemConfig });
});
`,
    sampleErrorLogs: `[2026-10-24 14:15:02] ERROR [WebhookService] Request to metadata endpoint initiated:
Target: http://169.254.169.254/latest/meta-data/iam/security-credentials/
AxiosError: connect ECONNREFUSED 169.254.169.254:80
  at AxiosError.from (/app/node_modules/axios/lib/core/AxiosError.js:89:14)
  at /app/webhook_processor.ts:28:34
[2026-10-24 14:18:19] WARN [NodeRuntime] Object prototype mutation detected.
Payload contained '__proto__.isAdmin: true' triggering privilege escalation.
`
  },
  {
    id: 'go-path-traversal',
    name: 'Go (Path Traversal & Resource Exhaustion)',
    language: 'go',
    filename: 'filestore.go',
    description: 'Vulnerabilidade de Directory/Path Traversal permitindo leitura arbitrária de arquivos do sistema operacional.',
    code: `package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const StorageDir = "/var/app/uploads"

// VULNERABILITY: Path Traversal (CWE-22)
// filepath.Join não impede sequências "../" se o path resultante não for validado
func DownloadFileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	if filename == "" {
		http.Error(w, "Parametro 'file' ausente", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(StorageDir, filename)

	// Inseguro: permite "../../../../etc/passwd"
	file, err := os.Open(targetPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Arquivo nao encontrado: %v", err), http.StatusNotFound)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, file)
}

func main() {
	http.HandleFunc("/download", DownloadFileHandler)
	http.ListenAndServe(":8080", nil)
}
`,
    sampleErrorLogs: `2026/10/24 11:05:42 [SECURITY-ALERT] Path traversal probe detected from IP 198.51.100.24
GET /download?file=../../../../etc/shadow HTTP/1.1
os.Open(/var/app/uploads/../../../../etc/shadow): open /etc/shadow: permission denied
FileHandler goroutine exited with status 404
`
  },
  {
    id: 'java-xxe-deserialization',
    name: 'Java (Spring Boot - Unsafe Deserialization & XXE)',
    language: 'java',
    filename: 'PaymentBatchController.java',
    description: 'Vulnerabilidades críticas: Deserialização insegura de objetos binários e processamento de XML com entidades externas ativadas.',
    code: `package com.aegis.security.controller;

import org.springframework.web.bind.annotation.*;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.*;

@RestController
@RequestMapping("/api/payments")
public class PaymentBatchController {

    // VULNERABILITY 1: Insecure Object Deserialization (CWE-502)
    @PostMapping("/restore-session")
    public String restoreSession(@RequestBody byte[] rawPayload) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(rawPayload);
        // Deserialização direta sem lista de permissão de classes (RCE Risk)
        ObjectInputStream ois = new ObjectInputStream(bis);
        Object sessionData = ois.readObject();
        return "Sessao restaurada: " + sessionData.toString();
    }

    // VULNERABILITY 2: XML External Entity (XXE) Injection (CWE-611)
    @PostMapping("/parse-invoice")
    public String parseInvoice(@RequestBody String xmlContent) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Faltam as proteções setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        // Permite ataque com <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xmlContent.getBytes()));
        return doc.getDocumentElement().getTextContent();
    }
}
`,
    sampleErrorLogs: `2026-10-24 09:12:33.402 ERROR 1 --- [nio-8080-exec-4] c.a.s.c.PaymentBatchController :
java.io.InvalidClassException: org.apache.commons.collections.functors.InvokerTransformer;
local class incompatible: stream classdesc serialVersionUID = 47829124018, local class = 202410
  at java.io.ObjectStreamClass.initNonProxy(ObjectStreamClass.java:699)
  at java.io.ObjectInputStream.readClassDesc(ObjectInputStream.java:1914)
  at com.aegis.security.controller.PaymentBatchController.restoreSession(PaymentBatchController.java:18)
[ATTACK TRIGGERED] Gadget chain execution intercepted in Sandbox!
`
  },
  {
    id: 'dockerfile-insecure',
    name: 'Dockerfile (Hardcoded Secrets & Root Privileges)',
    language: 'dockerfile',
    filename: 'Dockerfile',
    description: 'Misconfigurations de segurança em contêineres: execução contínua como root e chaves privadas embutidas nas camadas.',
    code: `FROM node:18-alpine

# VULNERABILITY 1: Hardcoded Secrets in Image Layers (CWE-798)
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# VULNERABILITY 2: Running container as ROOT user (CWE-250)
# Falta declarar "USER node" antes do CMD
EXPOSE 3000

CMD ["node", "server.js"]
`,
    sampleErrorLogs: `Container Security Scan (Trivy / Aegis Daemon):
- CRITICAL: Root user detected in final execution layer (UID 0). Potential container breakout.
- HIGH: Leaked AWS credential pattern matched in environment variable 'AWS_SECRET_ACCESS_KEY'.
`
  }
];

export const SUPPORTED_LANGUAGES = [
  { id: 'python', label: 'Python', ext: '.py' },
  { id: 'typescript', label: 'TypeScript', ext: '.ts' },
  { id: 'javascript', label: 'JavaScript', ext: '.js' },
  { id: 'go', label: 'Go (Golang)', ext: '.go' },
  { id: 'java', label: 'Java', ext: '.java' },
  { id: 'rust', label: 'Rust', ext: '.rs' },
  { id: 'c', label: 'C / C++', ext: '.c' },
  { id: 'php', label: 'PHP', ext: '.php' },
  { id: 'ruby', label: 'Ruby', ext: '.rb' },
  { id: 'csharp', label: 'C# / .NET', ext: '.cs' },
  { id: 'dockerfile', label: 'Dockerfile', ext: 'Dockerfile' },
  { id: 'sql', label: 'SQL', ext: '.sql' }
];
