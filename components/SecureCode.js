"use client";
import { useMemo, useState } from "react";

const samples = {
  javascript: `const express = require("express");
const { exec } = require("child_process");
const app = express();

const API_KEY = "sk_live_super_secret_123456";

app.get("/users", (req, res) => {
  const sql = "SELECT * FROM users WHERE email = '" + req.query.email + "'";
  db.query(sql, (err, rows) => res.json(rows));
});

app.post("/convert", (req, res) => {
  exec("convert " + req.body.filename, (err, output) => {
    console.log("token", req.body.token);
    res.send(output);
  });
});

app.listen(3000);`,
  python: `from flask import Flask, request
import sqlite3
import subprocess

app = Flask(__name__)
SECRET_KEY = "production-secret-key-123"

@app.route("/profile")
def profile():
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + user_id
    return str(sqlite3.connect("app.db").execute(query).fetchall())

@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping " + host, shell=True)
`,
  safe: `import { z } from "zod";

const requestSchema = z.object({
  email: z.string().email().max(120)
});

export async function findUser(req, res) {
  const { email } = requestSchema.parse(req.body);
  const user = await db.query(
    "SELECT id, email FROM users WHERE email = ?",
    [email]
  );
  res.json(user);
}`
};

async function reviewCode(code,language){
  const response=await fetch("/api/review",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({code,language})});
  const data=await response.json();
  if(!response.ok)throw new Error(data.error||"Review failed");
  return data;
}

export default function SecureCode(){
  const [code,setCode]=useState("");
  const [language,setLanguage]=useState("javascript");
  const [result,setResult]=useState(null);
  const [loading,setLoading]=useState(false);
  const [error,setError]=useState("");
  const [filter,setFilter]=useState("all");
  const [selected,setSelected]=useState(null);
  const lines=useMemo(()=>code.split("\n"),[code]);
  const filtered=result?.findings.filter(item=>filter==="all"||item.severity===filter)||[];
  async function run(){if(code.trim().length<10){setError("Paste a meaningful code sample to review.");return}setLoading(true);setError("");setResult(null);setSelected(null);try{const data=await reviewCode(code,language);setResult(data);setSelected(data.findings[0]||null);setTimeout(()=>document.querySelector(".review")?.scrollIntoView({behavior:"smooth",block:"start"}),50)}catch(err){setError(err.message)}finally{setLoading(false)}}
  function useSample(kind){setLanguage(kind==="python"?"python":"javascript");setCode(samples[kind]);setResult(null);setError("")}
  return <main>
    <header><a className="brand" href="#"><span className="brandMark"><svg viewBox="0 0 32 32"><path d="M16 3 27 8v8c0 7-4.7 11.2-11 13-6.3-1.8-11-6-11-13V8l11-5Z"/><path d="m9 13 5 3-5 3m10-6-5 9m4-3h5"/></svg></span><span>SECURE<span>CODE AI</span></span></a><div className="aiStatus"><i/> GEMINI + STATIC ANALYSIS</div></header>
    <section className="hero"><div className="eyebrow">PROJECT 10 <i/> SECURE CODING LAB</div><h1>Ship code.<br/><em>Not vulnerabilities.</em></h1><p>Paste a code sample to find exposed secrets, injection risks, unsafe patterns, and missing validation before they reach production.</p><div className="privacyNote"><span>AI REVIEW NOTICE</span><strong>Code is sent to Google Gemini for this review. Never paste private production code or real credentials.</strong></div></section>
    <section className="workspace">
      <div className="editorPanel"><div className="panelHead"><div><span>01</span><h2>Code workspace</h2></div><div className="language"><span>LANGUAGE</span><select value={language} onChange={e=>setLanguage(e.target.value)}><option value="javascript">JavaScript</option><option value="typescript">TypeScript</option><option value="python">Python</option><option value="java">Java</option><option value="sql">SQL</option><option value="html">HTML</option><option value="other">Other</option></select></div></div><div className="codeEditor"><div className="lineNumbers">{lines.map((_,i)=><span key={i}>{i+1}</span>)}</div><textarea value={code} onChange={e=>{setCode(e.target.value);setResult(null);setError("")}} maxLength="20000" spellCheck="false" placeholder="// Paste code here for a defensive security review..."/></div><div className="editorFoot"><span>Use sample or fictional code only</span><b>{code.length.toLocaleString()} / 20,000</b></div><div className="sampleRow"><span>LOAD SAMPLE</span><button onClick={()=>useSample("javascript")}>Vulnerable Node.js</button><button onClick={()=>useSample("python")}>Vulnerable Python</button><button onClick={()=>useSample("safe")}>Safer code</button><button onClick={()=>{setCode("");setResult(null)}}>Clear</button></div>{error&&<p className="error">{error}</p>}<button className="reviewButton" onClick={run} disabled={loading}>{loading?"Reviewing with Gemini...":"Run security review"}<span>→</span></button></div>
      <aside className="readyPanel"><div className={`aiCore ${loading?"thinking":""}`}><span>AI</span><i/><i/><i/></div><strong>{loading?"Analyzing attack paths":"Ready to review"}</strong><p>{loading?"Static rules run first while Gemini evaluates context and safer alternatives.":"Results combine deterministic pattern checks with an AI-assisted semantic review."}</p><div className="layers"><span>STATIC RULES <b>ON</b></span><span>GEMINI REVIEW <b>ON</b></span><span>SECRET REDACTION <b>ON</b></span></div></aside>
    </section>
    {result&&<Review result={result} selected={selected} setSelected={setSelected} filter={filter} setFilter={setFilter} filtered={filtered}/>}
    <section className="learn"><div className="learnHead"><span>04 / REVIEW MINDSET</span><h2>Security review asks<br/>what an attacker controls.</h2></div><div className="learnGrid"><article><span>01</span><h3>Trace untrusted data</h3><p>Follow request values through queries, templates, paths, commands, logs, and responses.</p></article><article><span>02</span><h3>Check authorization</h3><p>Authentication identifies a caller. Every sensitive object and action still needs permission checks.</p></article><article><span>03</span><h3>Reduce exposure</h3><p>Keep secrets out of source, return only necessary fields, and avoid sensitive logs and errors.</p></article><article><span>04</span><h3>Design safer defaults</h3><p>Parameterized APIs, schemas, escaping, least privilege, and secure libraries remove entire bug classes.</p></article></div></section>
    <footer><a className="brand" href="#"><span className="brandMark">&lt;/&gt;</span><span>SECURE<span>CODE AI</span></span></a><p>AI-assisted review can miss vulnerabilities. Use tests, human review, and security tooling together.</p><span>NEXT.JS · GEMINI · 2026</span></footer>
  </main>
}

function Review({result,selected,setSelected,filter,setFilter,filtered}){
  const counts={critical:0,high:0,medium:0,low:0};result.findings.forEach(x=>counts[x.severity]++);
  const scoreTone=result.score>=85?"good":result.score>=60?"medium":"poor";
  return <section className="review">
    <div className="scorePanel"><span className="sectionLabel">02 / SECURITY SCORE</span><div className={`scoreRing ${scoreTone}`} style={{"--score":result.score}}><strong>{result.score}</strong><small>/100</small></div><span className={`scorePill ${scoreTone}`}>{result.score>=85?"Stronger baseline":result.score>=60?"Needs improvement":"High risk"}</span><h2>{result.summary}</h2><div className="sourceBadge"><i className={result.aiUsed?"active":""}/>{result.aiUsed?"Gemini review completed":"Static analysis only"}</div>{result.aiError&&<p className="aiError">{result.aiError}</p>}<div className="severityStats">{Object.entries(counts).map(([key,value])=><span key={key} className={key}>{value}<small>{key.toUpperCase()}</small></span>)}</div></div>
    <div className="findingsPanel"><div className="findingsHead"><div><span className="sectionLabel">03 / SECURITY FINDINGS</span><h2>{result.findings.length} issues to review</h2></div><div className="filters">{["all","critical","high","medium","low"].map(key=><button className={filter===key?"active":""} onClick={()=>setFilter(key)} key={key}>{key}</button>)}</div></div><div className="findingList">{filtered.length?filtered.map(item=><button className={`${item.severity} ${selected?.id===item.id?"selected":""}`} key={item.id} onClick={()=>setSelected(item)}><span className="severityIcon">!</span><div><strong>{item.title}</strong><small>Line {item.line} · {item.category} · {item.source==="gemini"?"Gemini":"Static rule"}</small></div><b>{item.severity}</b><i>→</i></button>):<div className="noFindings">No findings in this severity filter.</div>}</div></div>
    <aside className="detailPanel">{selected?<FindingDetail item={selected}/>:<div className="emptyDetail">Select a finding to view the explanation and safer code.</div>}</aside>
  </section>
}

function FindingDetail({item}){
  return <div><div className="detailHead"><span>FINDING DETAIL</span><b className={item.severity}>{item.severity}</b></div><h2>{item.title}</h2><div className="meta"><span>LINE {item.line}</span><span>{item.category.toUpperCase()}</span><span>{item.source==="gemini"?"AI REVIEW":"STATIC RULE"}</span></div><section><span>WHY IT MATTERS</span><p>{item.explanation}</p></section><div className="evidence"><span>MATCHED EVIDENCE</span><code>{redact(item.evidence)}</code></div><section><span>BEGINNER-FRIENDLY FIX</span><p>{item.fix}</p></section><div className="safer"><span>SAFER PATTERN</span><pre><code>{item.safer}</code></pre></div></div>
}

function redact(value=""){
  return value.replace(/(["'`])([^"'`\n]{12,})\1/g,(match,quote,body)=>`${quote}${body.slice(0,4)}…REDACTED${quote}`);
}
