const rules = [
  {
    id: "hardcoded-secret", title: "Possible hardcoded secret", severity: "critical", category: "Secrets",
    patterns: [/\b(?:api[_-]?key|secret|password|passwd|token|private[_-]?key)\s*[:=]\s*["'`][^"'`\n]{8,}["'`]/gi, /\bAIza[0-9A-Za-z_-]{25,}\b/g],
    explanation: "Secrets stored in source code can leak through repositories, logs, builds, or screenshots.",
    fix: "Read secrets from a server-side environment variable or managed secret store. Rotate any exposed value.",
    safer: `const apiKey = process.env.API_KEY;\nif (!apiKey) throw new Error("Missing API_KEY");`
  },
  {
    id: "sql-injection", title: "SQL built with user-controlled text", severity: "critical", category: "Injection",
    patterns: [/(?:SELECT|INSERT|UPDATE|DELETE)[^;\n]*(?:\+|\$\{)[^;\n]*(?:req\.|request\.|input|user)/gi, /\.query\(\s*[`"'][^)]*\$\{/gi],
    explanation: "Combining input with SQL can let an attacker change the query.",
    fix: "Use parameterized queries or an ORM that binds values separately.",
    safer: `db.query("SELECT * FROM users WHERE email = ?", [email]);`
  },
  {
    id: "command-injection", title: "Command execution with dynamic input", severity: "critical", category: "Injection",
    patterns: [/\b(?:exec|execSync|system|popen)\s*\([^)]*(?:req\.|request\.|input|user|\$\{|\+)/gi, /subprocess\.[^(]+\([^)]*shell\s*=\s*True/gi],
    explanation: "User-controlled shell commands can execute arbitrary operating-system instructions.",
    fix: "Avoid the shell. Use fixed commands, argument arrays, allowlists, and least-privilege processes.",
    safer: `spawn("convert", ["--format", allowedFormat, inputPath], { shell: false });`
  },
  {
    id: "code-execution", title: "Dynamic code execution", severity: "high", category: "Unsafe execution",
    patterns: [/\beval\s*\(/g, /\bnew Function\s*\(/g, /\bexec\s*\(\s*(?:input|request|req\.)/g],
    explanation: "Dynamic evaluation treats text as executable code and can turn input into commands.",
    fix: "Replace evaluation with explicit parsing, mapping, or a narrow allowlist of supported operations.",
    safer: `const operations = { add: (a, b) => a + b };\nconst result = operations[action]?.(a, b);`
  },
  {
    id: "xss", title: "Unsafe HTML insertion", severity: "high", category: "Browser security",
    patterns: [/\.innerHTML\s*=/g, /dangerouslySetInnerHTML\s*=/g, /document\.write\s*\(/g],
    explanation: "Untrusted HTML can execute scripts in another user's browser.",
    fix: "Render text by default. If HTML is required, sanitize it with a maintained, context-aware library.",
    safer: `element.textContent = userMessage;`
  },
  {
    id: "weak-crypto", title: "Weak cryptographic algorithm", severity: "high", category: "Cryptography",
    patterns: [/\b(?:md5|sha1)\s*\(/gi, /createHash\(\s*["'](?:md5|sha1)["']\s*\)/gi, /\bDES\b/g],
    explanation: "Old hash and cipher algorithms are not suitable for passwords or modern security decisions.",
    fix: "Use Argon2id, scrypt, or bcrypt for passwords; use SHA-256+ for integrity and authenticated encryption for data.",
    safer: `const hash = await bcrypt.hash(password, 12);`
  },
  {
    id: "weak-validation", title: "Input used without clear validation", severity: "medium", category: "Validation",
    patterns: [/\breq\.(?:body|query|params)\.[A-Za-z_$][\w$]*\b/g, /\brequest\.(?:form|args|json)\b/g],
    explanation: "Request values are attacker-controlled and may have unexpected types, lengths, or formats.",
    fix: "Validate on the server with a schema before the value reaches databases, files, templates, or commands.",
    safer: `const input = schema.parse(req.body);`
  },
  {
    id: "path-traversal", title: "Dynamic filesystem path", severity: "high", category: "Filesystem",
    patterns: [/(?:readFile|writeFile|unlink|sendFile|open)\s*\([^)]*(?:req\.|request\.|input|user)/gi, /path\.join\([^)]*(?:req\.|input|user)/gi],
    explanation: "An attacker may use ../ sequences or absolute paths to access unintended files.",
    fix: "Resolve against a fixed base directory, reject traversal, and use generated identifiers instead of raw filenames.",
    safer: `const target = path.resolve(BASE_DIR, safeId);\nif (!target.startsWith(BASE_DIR)) throw new Error("Invalid path");`
  },
  {
    id: "cors", title: "Overly broad CORS policy", severity: "medium", category: "Configuration",
    patterns: [/Access-Control-Allow-Origin["']?\s*[:,=]\s*["']\*["']/gi, /\bcors\(\s*\)/g, /allow_origins\s*=\s*\[\s*["']\*["']\s*\]/gi],
    explanation: "Allowing every origin can expose authenticated APIs to untrusted websites.",
    fix: "Allow only the known application origins and review credential handling.",
    safer: `cors({ origin: ["https://app.example.com"], credentials: true })`
  },
  {
    id: "insecure-http", title: "Insecure HTTP endpoint", severity: "medium", category: "Transport",
    patterns: [/http:\/\/(?!localhost|127\.0\.0\.1)[^\s"'`]+/gi],
    explanation: "Plain HTTP can expose or alter data in transit.",
    fix: "Use HTTPS and verify certificates. Never send credentials or tokens over HTTP.",
    safer: `const API_URL = "https://api.example.com";`
  },
  {
    id: "sensitive-log", title: "Sensitive data may be logged", severity: "medium", category: "Data exposure",
    patterns: [/(?:console\.log|logger\.\w+|print)\s*\([^)]*(?:password|token|secret|card|authorization)/gi],
    explanation: "Logs are widely accessible and often retained longer than application data.",
    fix: "Log event metadata, not credentials or full personal data. Add redaction at the logging layer.",
    safer: `logger.info("Login attempt", { userId, outcome });`
  }
];

function lineNumber(code, index) {
  return code.slice(0, index).split("\n").length;
}

export function reviewStatic(code) {
  const findings = [];
  rules.forEach(rule => {
    const seen = new Set();
    rule.patterns.forEach(pattern => {
      pattern.lastIndex = 0;
      for (const match of code.matchAll(pattern)) {
        const line = lineNumber(code, match.index);
        const key = `${rule.id}:${line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          id: key,
          title: rule.title,
          severity: rule.severity,
          category: rule.category,
          line,
          evidence: match[0].slice(0, 140),
          explanation: rule.explanation,
          fix: rule.fix,
          safer: rule.safer,
          source: "static"
        });
      }
    });
  });
  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  findings.sort((a,b) => order[b.severity] - order[a.severity] || a.line - b.line);
  return findings.slice(0, 20);
}

export function securityScore(findings) {
  const weights = { critical: 24, high: 14, medium: 7, low: 3 };
  return Math.max(0, 100 - findings.reduce((sum,item)=>sum+(weights[item.severity]||0),0));
}

