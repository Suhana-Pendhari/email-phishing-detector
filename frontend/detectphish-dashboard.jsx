import { useState, useEffect, useRef } from "react";
import { Shield, AlertTriangle, Search, Upload, Zap, Brain, BookOpen, ChevronDown, ChevronRight, ExternalLink, Cpu, Eye, FileText, Activity, Mail, Link2 } from "lucide-react";

const LOGO_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="42" height="42"><defs><linearGradient id="sg" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:#38bdf8"/><stop offset="100%" style="stop-color:#818cf8"/></linearGradient></defs><circle cx="256" cy="256" r="240" fill="#0a0e14"/><circle cx="256" cy="256" r="240" fill="none" stroke="url(#sg)" stroke-width="3" opacity="0.4"/><path d="M310 45Q310 120 300 170Q290 220 280 260Q270 290 265 310" fill="none" stroke="rgba(56,189,248,0.5)" stroke-width="2.5" stroke-linecap="round"/><line x1="280" y1="35" x2="340" y2="55" stroke="#64748b" stroke-width="4" stroke-linecap="round"/><circle cx="310" cy="45" r="3" fill="#38bdf8" opacity="0.8"/><path d="M265 310L265 340Q265 380 240 395Q215 410 200 395Q185 380 200 365L215 355L205 345" fill="none" stroke="#94a3b8" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/><g transform="translate(256,300) rotate(-12)"><rect x="-75" y="-45" width="150" height="100" rx="8" fill="#1e293b" stroke="#334155" stroke-width="2"/><path d="M-75-45L0 15L75-45" fill="#334155" stroke="#475569" stroke-width="1.5"/><text x="0" y="45" text-anchor="middle" font-family="Arial" font-size="28" font-weight="700" fill="#38bdf8" opacity="0.6">@</text><g transform="translate(48,-28)"><polygon points="0,-14 12,10 -12,10" fill="#f87171" stroke="#fca5a5" stroke-width="1"/><text x="0" y="7" text-anchor="middle" font-family="Arial" font-size="14" font-weight="900" fill="white">!</text></g></g></svg>`;

const C = {
  bg: "#0a0e14", surface: "#0f1419", card: "#141a22",
  border: "#1e2a3a", borderHover: "#2d3f56",
  text: "#c8d1dc", textBright: "#e8edf3", textMuted: "#5c6b7f",
  accent: "#38bdf8", accentDim: "rgba(56,189,248,0.08)",
  green: "#34d399", greenDim: "rgba(52,211,153,0.1)",
  red: "#f87171", redDim: "rgba(248,113,113,0.1)",
  orange: "#fbbf24", orangeDim: "rgba(251,191,36,0.1)",
  purple: "#a78bfa", purpleDim: "rgba(167,139,250,0.1)",
};

const DEMO_EMAILS = [
  { name: "PayPal phishing", subject: "Your account has been limited",
    text: `Dear Valued Customer,\n\nWe've noticed unusual activity on your PayPal account. Your account has been temporarily limited until we can verify your identity.\n\nYou must verify your account within 24 hours or your account will be permanently suspended.\n\nClick here to verify your account: https://paypa1-secure.verification-center.xyz/login/verify?id=83721\n\nIf you don't verify within 24 hours, we will be forced to permanently close your account and you will lose access to your funds.\n\nThank you,\nPayPal Security Team\nsecurity-noreply@paypal-alerts.com`,
    headers: `From: "PayPal Security" <security-noreply@paypal-alerts.com>\nTo: user@example.com\nReply-To: support@pp-verify.xyz\nSubject: Your account has been limited\nAuthentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\nX-Mailer: PHPMailer 6.1.4` },
  { name: "Legitimate newsletter", subject: "This week in tech",
    text: `Hi Alex,\n\nHere's your weekly roundup of the biggest stories in technology.\n\n1. The EU passed new AI safety regulations this week.\n2. SpaceX successfully launched its latest Starship test flight.\n3. Mozilla released Firefox 130 with improved privacy features.\n\nYou can update your preferences or unsubscribe at any time.\n\nBest,\nTechDigest Editorial Team\n\n© 2026 TechDigest Media Inc.`,
    headers: `From: "TechDigest" <newsletter@techdigest.com>\nTo: alex@example.com\nAuthentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass` },
  { name: "CEO fraud / BEC", subject: "Urgent wire transfer needed",
    text: `Hi,\n\nI need you to process an urgent wire transfer today. I'm in a meeting and can't call right now.\n\nPlease wire $47,500 to the following account immediately:\n\nBank: First National Bank\nAccount: 8829471023\nRouting: 021000089\nBeneficiary: Greenfield Consulting LLC\n\nThis is for the acquisition deal we discussed. It needs to go out before 3pm EST today. Don't discuss this with anyone else until the deal closes.\n\nLet me know once it's done.\n\nSent from my iPhone`,
    headers: `From: "David Chen - CEO" <d.chen@company-corp.com>\nTo: accounting@company.com\nReply-To: dchen.ceo@gmail.com\nAuthentication-Results: mx.company.com; spf=softfail; dkim=none; dmarc=fail` },
];

const SeverityBadge = ({ severity }) => {
  const m = { critical: C.red, high: C.orange, medium: C.orange, low: C.green, info: C.textMuted };
  const c = m[severity] || C.textMuted;
  return <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: `${c}18`, color: c, fontFamily: "var(--mono)" }}><span style={{ width: 5, height: 5, borderRadius: "50%", background: c }} />{severity}</span>;
};

const VerdictDisplay = ({ verdict, score }) => {
  const m = { phishing: { color: C.red, bg: C.redDim, label: "PHISHING" }, suspicious: { color: C.orange, bg: C.orangeDim, label: "SUSPICIOUS" }, legitimate: { color: C.green, bg: C.greenDim, label: "LEGITIMATE" } };
  const v = m[verdict] || m.suspicious;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
      <div style={{ fontSize: 48, fontWeight: 800, fontFamily: "var(--mono)", color: v.color, lineHeight: 1 }}>{Math.round(score)}</div>
      <div>
        <div style={{ fontSize: 10, color: C.textMuted, fontFamily: "var(--mono)", letterSpacing: "0.1em", marginBottom: 4 }}>PHISHING SCORE</div>
        <span style={{ padding: "4px 12px", borderRadius: 4, fontSize: 11, fontWeight: 700, fontFamily: "var(--mono)", background: v.bg, color: v.color }}>{v.label}</span>
      </div>
    </div>
  );
};

const LayerCard = ({ icon: Icon, title, subtitle, color, active, score, children }) => (
  <div style={{ background: C.card, border: `1px solid ${active ? color + "40" : C.border}`, borderRadius: 10, borderTop: `2px solid ${color}`, overflow: "hidden" }}>
    <div style={{ padding: "14px 18px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <Icon size={16} color={color} />
        <div><div style={{ fontSize: 13, fontWeight: 700, color: C.textBright }}>{title}</div><div style={{ fontSize: 10, color: C.textMuted, fontFamily: "var(--mono)" }}>{subtitle}</div></div>
      </div>
      {active && score !== undefined && <span style={{ fontSize: 18, fontWeight: 800, fontFamily: "var(--mono)", color }}>{score}</span>}
      {!active && <span style={{ fontSize: 10, color: C.textMuted, fontFamily: "var(--mono)" }}>INACTIVE</span>}
    </div>
    {children && <div style={{ borderTop: `1px solid ${C.border}`, padding: "14px 18px" }}>{children}</div>}
  </div>
);

const FindingRow = ({ finding, defaultOpen = false }) => {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ borderBottom: `1px solid ${C.border}`, padding: "10px 0" }}>
      <div onClick={() => setOpen(!open)} style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
        {open ? <ChevronDown size={14} color={C.textMuted} /> : <ChevronRight size={14} color={C.textMuted} />}
        <SeverityBadge severity={finding.severity} />
        <span style={{ fontSize: 12, fontWeight: 600, color: C.textBright, flex: 1 }}>{finding.name}</span>
        <span style={{ fontSize: 10, color: C.textMuted, fontFamily: "var(--mono)" }}>{finding.rule_id}</span>
      </div>
      {open && (
        <div style={{ marginTop: 8, marginLeft: 22, fontSize: 12, color: C.text, lineHeight: 1.6 }}>
          {finding.description}
          {(finding.raw_value || finding.evidence || finding.url) && (
            <div style={{ marginTop: 6, padding: "6px 10px", background: C.bg, borderRadius: 4, fontFamily: "var(--mono)", fontSize: 11, color: C.textMuted, wordBreak: "break-all" }}>
              {finding.raw_value || finding.evidence || finding.url}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const VtVerdictBadge = ({ verdict }) => {
  const color = verdict === "malicious" ? C.red : verdict === "suspicious" ? C.orange : verdict === "clean" ? C.green : C.textMuted;
  return <span style={{ padding: "2px 10px", borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: "var(--mono)", background: `${color}20`, color, whiteSpace: "nowrap" }}>{(verdict || "unknown").toUpperCase()}</span>;
};

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function DetectPhish() {
  // Core state
  const [emailText, setEmailText] = useState("");
  const [headers, setHeaders] = useState("");
  const [subject, setSubject] = useState("");
  const [results, setResults] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState("input");
  const [showHeaders, setShowHeaders] = useState(false);
  const [apiConnected, setApiConnected] = useState(null);
  const [aiStatus, setAiStatus] = useState(null);
  const [aiExpanded, setAiExpanded] = useState(false);

  // EML upload
  const [dragging, setDragging] = useState(false);
  const [emlInfo, setEmlInfo] = useState(null);

  // Attachment VT scanning (input tab)
  const [attachFile, setAttachFile] = useState(null);
  const [attachVtMode, setAttachVtMode] = useState("hash");
  const [attachVtResult, setAttachVtResult] = useState(null);
  const [attachVtLoading, setAttachVtLoading] = useState(false);

  // Auto-detected URLs + VT prompt (results tab)
  const [detectedUrls, setDetectedUrls] = useState([]);
  const [showVtPrompt, setShowVtPrompt] = useState(false);
  const [urlVtResults, setUrlVtResults] = useState(null);
  const [urlVtLoading, setUrlVtLoading] = useState(false);

  // Standalone VT tab
  const [vtTabUrls, setVtTabUrls] = useState("");
  const [vtTabUrlResults, setVtTabUrlResults] = useState(null);
  const [vtTabUrlLoading, setVtTabUrlLoading] = useState(false);
  const [vtTabFileResult, setVtTabFileResult] = useState(null);
  const [vtTabFileLoading, setVtTabFileLoading] = useState(false);
  const [vtTabFileMode, setVtTabFileMode] = useState("hash");

  // Refs
  const textRef = useRef(null);
  const emlFileRef = useRef(null);
  const attachFileRef = useRef(null);
  const vtTabFileRef = useRef(null);

  // ── API health check ──
  useEffect(() => {
    fetch("http://localhost:5000/api/health").then(r => r.json())
      .then(d => { setApiConnected(true); setAiStatus(d); })
      .catch(() => setApiConnected(false));
  }, []);

  // ── Load demo email ──
  const loadDemo = (demo) => {
    setEmailText(demo.text); setHeaders(demo.headers); setSubject(demo.subject);
    setResults(null); setEmlInfo(null); setAttachFile(null); setAttachVtResult(null);
    setDetectedUrls([]); setUrlVtResults(null); setShowVtPrompt(false);
    setActiveTab("input");
  };

  // ── Analyze email (main) ──
  const analyze = async () => {
    if (!emailText.trim()) return;
    setAnalyzing(true); setActiveTab("results"); setUrlVtResults(null); setShowVtPrompt(false);
    // Detect URLs in email body
    const urls = [...new Set((emailText.match(/https?:\/\/[^\s<>"')\]]+/g) || []))];
    setDetectedUrls(urls);

    try {
      const resp = await fetch("http://localhost:5000/api/analyze", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email_text: emailText, headers, subject }),
      });
      const data = await resp.json();
      setResults(data);
      // Show VT prompt if URLs found
      if (urls.length > 0) setShowVtPrompt(true);
    } catch {
      setResults(generateDemoResults(emailText, subject));
      if (urls.length > 0) setShowVtPrompt(true);
    }
    setAnalyzing(false);
  };

  // ── EML upload ──
  const handleEmlUpload = async (file) => {
    if (!file || !file.name.toLowerCase().endsWith(".eml")) { alert("Please upload a .eml file"); return; }
    setAnalyzing(true); setActiveTab("results"); setEmlInfo({ filename: file.name, size: file.size });
    try {
      const fd = new FormData(); fd.append("file", file);
      const resp = await fetch("http://localhost:5000/api/upload-eml", { method: "POST", body: fd });
      const data = await resp.json();
      if (data.error) { alert(data.error); setAnalyzing(false); setActiveTab("input"); return; }
      if (data.eml) { setSubject(data.eml.subject || ""); setEmlInfo(prev => ({ ...prev, ...data.eml })); }
      setResults(data);
      const urls = [...new Set((data.eml?.body_text || "").match(/https?:\/\/[^\s<>"')\]]+/g) || [])];
      setDetectedUrls(urls);
      if (urls.length > 0) setShowVtPrompt(true);
    } catch { alert("Upload failed. Is the backend running?"); setActiveTab("input"); }
    setAnalyzing(false);
  };
  const handleDrop = (e) => { e.preventDefault(); setDragging(false); if (e.dataTransfer.files[0]) handleEmlUpload(e.dataTransfer.files[0]); };

  // ── Attachment VT scan (input tab) ──
  const scanAttachVt = async () => {
    if (!attachFile) return;
    setAttachVtLoading(true); setAttachVtResult(null);
    try {
      const fd = new FormData(); fd.append("file", attachFile);
      const resp = await fetch(`http://localhost:5000/api/vt/file?mode=${attachVtMode}`, { method: "POST", body: fd });
      setAttachVtResult(await resp.json());
    } catch { setAttachVtResult({ error: "API not reachable" }); }
    setAttachVtLoading(false);
  };

  // ── Scan detected URLs on VT (results tab) ──
  const scanDetectedUrlsVt = async () => {
    if (!detectedUrls.length) return;
    setUrlVtLoading(true); setShowVtPrompt(false);
    try {
      const resp = await fetch("http://localhost:5000/api/vt/urls", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ urls: detectedUrls }),
      });
      setUrlVtResults(await resp.json());
    } catch { setUrlVtResults({ error: "API not reachable" }); }
    setUrlVtLoading(false);
  };

  // ── VT tab: scan URLs ──
  const scanVtTabUrls = async () => {
    const urlList = vtTabUrls.split("\n").map(u => u.trim()).filter(u => u.startsWith("http"));
    if (!urlList.length) return;
    setVtTabUrlLoading(true); setVtTabUrlResults(null);
    try {
      const resp = await fetch("http://localhost:5000/api/vt/urls", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ urls: urlList }),
      });
      setVtTabUrlResults(await resp.json());
    } catch { setVtTabUrlResults({ error: "API not reachable" }); }
    setVtTabUrlLoading(false);
  };

  // ── VT tab: scan file ──
  const scanVtTabFile = async (file) => {
    if (!file) return;
    setVtTabFileLoading(true); setVtTabFileResult(null);
    try {
      const fd = new FormData(); fd.append("file", file);
      const resp = await fetch(`http://localhost:5000/api/vt/file?mode=${vtTabFileMode}`, { method: "POST", body: fd });
      setVtTabFileResult(await resp.json());
    } catch { setVtTabFileResult({ error: "API not reachable" }); }
    setVtTabFileLoading(false);
  };

  // ── Derived data ──
  const allFindings = results?.rules?.all_findings || [];
  const aiData = results?.ai || {};
  const combined = results?.combined || {};

  // ══════════════════════════════════════════════════════════════
  // RENDER
  // ══════════════════════════════════════════════════════════════

  return (
    <div style={{ background: C.bg, color: C.text, minHeight: "100vh", fontFamily: "'Outfit', 'SF Pro Display', system-ui, sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Outfit:wght@400;500;600;700;800&display=swap');
        :root { --mono: 'JetBrains Mono', monospace; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
        @keyframes scan { 0% { transform: translateX(-100%); } 100% { transform: translateX(200%); } }
        ::placeholder { color: ${C.textMuted}; }
        textarea:focus, input:focus { outline: none; border-color: ${C.accent} !important; }
        ::-webkit-scrollbar { width: 5px; } ::-webkit-scrollbar-track { background: ${C.bg}; } ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        * { box-sizing: border-box; }
      `}</style>

      {/* ── Header with Logo ── */}
      <div style={{ borderBottom: `1px solid ${C.border}`, padding: "12px 24px", display: "flex", justifyContent: "space-between", alignItems: "center", background: C.surface }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div dangerouslySetInnerHTML={{ __html: LOGO_SVG }} style={{ width: 42, height: 42, borderRadius: 8, overflow: "hidden", flexShrink: 0 }} />
          <div>
            <div style={{ fontSize: 15, fontWeight: 800, color: C.textBright }}>Detect<span style={{ color: C.accent }}>Phish</span></div>
            <div style={{ fontSize: 9, color: C.textMuted, fontFamily: "var(--mono)", letterSpacing: "0.12em" }}>AI-POWERED PHISHING DETECTION</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "5px 10px", borderRadius: 6, fontSize: 10, fontFamily: "var(--mono)", background: apiConnected ? C.greenDim : C.redDim, color: apiConnected ? C.green : C.red, border: `1px solid ${apiConnected ? C.green + "30" : C.red + "30"}` }}>
            <span style={{ width: 5, height: 5, borderRadius: "50%", background: apiConnected ? C.green : C.red, animation: apiConnected ? "pulse 2s infinite" : "none" }} />
            API {apiConnected ? "CONNECTED" : "OFFLINE"}
          </div>
          {aiStatus?.ai_available && (
            <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "5px 10px", borderRadius: 6, fontSize: 10, fontFamily: "var(--mono)", background: C.purpleDim, color: C.purple, border: `1px solid ${C.purple}30` }}>
              <Brain size={11} /> {aiStatus.ai_backend || "AI"}
            </div>
          )}
          {aiStatus?.vt_available && (
            <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "5px 10px", borderRadius: 6, fontSize: 10, fontFamily: "var(--mono)", background: C.greenDim, color: C.green, border: `1px solid ${C.green}30` }}>
              <Shield size={11} /> VT
            </div>
          )}
        </div>
      </div>

      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "24px" }}>

        {/* About Section */}
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "18px 22px", marginBottom: 20 }}>
          <div style={{ fontSize: 13, color: C.text, lineHeight: 1.7 }}>
            <span style={{ fontWeight: 700, color: C.textBright }}>DetectPhish</span> is an AI-powered phishing email detection tool that uses a three-layer analysis engine — a machine learning classifier trained on real phishing datasets, a rule-based engine checking for known attack patterns (SPF/DKIM failures, homoglyph URLs, urgency language), and a locally-running LLM that identifies social engineering tactics and maps them to MITRE ATT&CK techniques. Paste an email, upload a .eml file, or scan suspicious attachments and URLs through VirusTotal — all from one dashboard.
          </div>
        </div>

        {/* Demo Emails */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 11, color: C.textMuted, fontFamily: "var(--mono)", letterSpacing: "0.08em", marginBottom: 8 }}>TRY A DEMO EMAIL</div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {DEMO_EMAILS.map((demo, i) => (
              <button key={i} onClick={() => loadDemo(demo)} style={{ padding: "7px 14px", borderRadius: 6, border: `1px solid ${C.border}`, background: C.card, color: C.text, fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: "inherit" }}
                onMouseEnter={e => { e.target.style.borderColor = C.accent; e.target.style.color = C.accent; }}
                onMouseLeave={e => { e.target.style.borderColor = C.border; e.target.style.color = C.text; }}>
                {demo.name}
              </button>
            ))}
          </div>
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", gap: 2, marginBottom: 20, background: C.surface, borderRadius: 8, padding: 3, width: "fit-content" }}>
          {[{ id: "input", label: "Email Input", icon: Mail }, { id: "results", label: "Analysis Results", icon: Eye }, { id: "virustotal", label: "VirusTotal", icon: Shield }].map(tab => {
            const Icon = tab.icon; const active = activeTab === tab.id;
            return (
              <button key={tab.id} onClick={() => setActiveTab(tab.id)} style={{ display: "flex", alignItems: "center", gap: 6, padding: "8px 16px", borderRadius: 6, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600, fontFamily: "inherit", background: active ? C.accent : "transparent", color: active ? "#000" : C.textMuted }}>
                <Icon size={14} />{tab.label}
              </button>
            );
          })}
        </div>

        {/* ════════════════════════════════════════════════════════ */}
        {/* INPUT TAB                                               */}
        {/* ════════════════════════════════════════════════════════ */}
        {activeTab === "input" && (
          <div style={{ animation: "fadeIn 0.2s ease" }}>
            {/* EML Drop Zone */}
            <div onDrop={handleDrop} onDragOver={e => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)}
              onClick={() => emlFileRef.current?.click()}
              style={{ border: `2px dashed ${dragging ? C.accent : C.border}`, borderRadius: 10, padding: "24px", marginBottom: 18, textAlign: "center", cursor: "pointer", background: dragging ? C.accentDim : "transparent" }}>
              <input ref={emlFileRef} type="file" accept=".eml" style={{ display: "none" }} onChange={e => { if (e.target.files[0]) handleEmlUpload(e.target.files[0]); }} />
              <Upload size={24} color={dragging ? C.accent : C.textMuted} style={{ marginBottom: 8 }} />
              <div style={{ fontSize: 13, fontWeight: 600, color: dragging ? C.accent : C.textBright, marginBottom: 4 }}>Drop a .eml file here or click to upload</div>
              <div style={{ fontSize: 11, color: C.textMuted }}>Auto-extracts headers, body, subject, and attachments</div>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 18 }}>
              <div style={{ flex: 1, height: 1, background: C.border }} />
              <span style={{ fontSize: 11, color: C.textMuted, fontFamily: "var(--mono)" }}>OR PASTE MANUALLY</span>
              <div style={{ flex: 1, height: 1, background: C.border }} />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 14 }}>
              {/* Subject */}
              <div>
                <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: C.textMuted, fontFamily: "var(--mono)", letterSpacing: "0.06em", marginBottom: 6 }}>SUBJECT LINE</label>
                <input value={subject} onChange={e => setSubject(e.target.value)} placeholder="Optional — paste the email subject here"
                  style={{ width: "100%", padding: "10px 14px", borderRadius: 8, border: `1px solid ${C.border}`, background: C.card, color: C.textBright, fontSize: 13, fontFamily: "inherit" }} />
              </div>

              {/* Body */}
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                  <label style={{ fontSize: 11, fontWeight: 600, color: C.textMuted, fontFamily: "var(--mono)", letterSpacing: "0.06em" }}>EMAIL BODY</label>
                  <span style={{ fontSize: 10, color: C.textMuted, fontFamily: "var(--mono)" }}>{emailText.length} chars</span>
                </div>
                <textarea ref={textRef} value={emailText} onChange={e => setEmailText(e.target.value)} placeholder="Paste the full email text here..."
                  style={{ width: "100%", minHeight: 200, padding: "14px", borderRadius: 8, border: `1px solid ${C.border}`, background: C.card, color: C.textBright, fontSize: 13, fontFamily: "var(--mono)", lineHeight: 1.6, resize: "vertical" }} />
              </div>

              {/* Headers (collapsible) */}
              <div>
                <button onClick={() => setShowHeaders(!showHeaders)} style={{ background: "none", border: "none", cursor: "pointer", display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: C.textMuted, fontFamily: "var(--mono)", padding: 0, marginBottom: showHeaders ? 6 : 0 }}>
                  {showHeaders ? <ChevronDown size={12} /> : <ChevronRight size={12} />} OPTIONAL: EMAIL HEADERS
                </button>
                {showHeaders && <textarea value={headers} onChange={e => setHeaders(e.target.value)} placeholder="Paste raw email headers for SPF/DKIM/DMARC analysis..."
                  style={{ width: "100%", minHeight: 100, padding: "14px", borderRadius: 8, border: `1px solid ${C.border}`, background: C.card, color: C.textBright, fontSize: 12, fontFamily: "var(--mono)", lineHeight: 1.5, resize: "vertical" }} />}
              </div>

              {/* ── Attachment Upload for VT ── */}
              <div>
                <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: C.textMuted, fontFamily: "var(--mono)", letterSpacing: "0.06em", marginBottom: 6 }}>OPTIONAL: ATTACHMENT — SCAN ON VIRUSTOTAL</label>
                <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, padding: "14px 16px", background: C.card, display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
                  <div style={{ flex: 1, minWidth: 180 }}>
                    <input ref={attachFileRef} type="file" style={{ display: "none" }} onChange={e => { setAttachFile(e.target.files[0] || null); setAttachVtResult(null); }} />
                    <button onClick={() => attachFileRef.current?.click()} style={{ padding: "8px 16px", borderRadius: 6, border: `1px solid ${C.border}`, background: "transparent", color: C.text, fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: "inherit", display: "flex", alignItems: "center", gap: 6 }}>
                      <Upload size={13} /> {attachFile ? attachFile.name : "Choose file"}
                    </button>
                    {attachFile && <div style={{ fontSize: 10, color: C.textMuted, fontFamily: "var(--mono)", marginTop: 4 }}>{(attachFile.size / 1024).toFixed(1)} KB</div>}
                  </div>
                  {attachFile && (
                    <>
                      <div style={{ display: "flex", gap: 3, background: C.bg, borderRadius: 6, padding: 2 }}>
                        {[{ id: "hash", label: "Hash lookup" }, { id: "full", label: "Full scan" }].map(m => (
                          <button key={m.id} onClick={() => setAttachVtMode(m.id)} style={{ padding: "5px 12px", borderRadius: 5, border: "none", cursor: "pointer", fontSize: 10, fontWeight: 600, fontFamily: "var(--mono)", background: attachVtMode === m.id ? C.purple : "transparent", color: attachVtMode === m.id ? "#000" : C.textMuted }}>{m.label}</button>
                        ))}
                      </div>
                      <button onClick={scanAttachVt} disabled={attachVtLoading} style={{ padding: "8px 16px", borderRadius: 6, border: "none", cursor: "pointer", background: C.purple, color: "#000", fontSize: 12, fontWeight: 700, fontFamily: "inherit", display: "flex", alignItems: "center", gap: 6, opacity: attachVtLoading ? 0.7 : 1 }}>
                        {attachVtLoading ? <><Activity size={12} style={{ animation: "pulse 1s infinite" }} /> Scanning...</> : <><Shield size={12} /> Scan on VT</>}
                      </button>
                    </>
                  )}
                </div>
                {/* Inline VT result */}
                {attachVtResult && !attachVtResult.error && (
                  <div style={{ marginTop: 10, padding: "12px 14px", background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                      <span style={{ fontSize: 12, fontWeight: 600, color: C.textBright }}>{attachVtResult.filename || attachFile?.name}</span>
                      <VtVerdictBadge verdict={attachVtResult.verdict} />
                    </div>
                    {attachVtResult.found ? (
                      <div style={{ display: "flex", gap: 16, fontSize: 11, color: C.textMuted }}>
                        <span>Detections: <span style={{ color: attachVtResult.malicious_count > 0 ? C.red : C.green, fontWeight: 700 }}>{attachVtResult.malicious_count}/{attachVtResult.total_engines}</span></span>
                        <span>Rate: <span style={{ color: C.textBright, fontWeight: 600 }}>{attachVtResult.detection_rate}%</span></span>
                        {attachVtResult.vt_link && <a href={attachVtResult.vt_link} target="_blank" rel="noopener noreferrer" style={{ color: C.accent, textDecoration: "none" }}>View on VT ↗</a>}
                      </div>
                    ) : <div style={{ fontSize: 11, color: C.orange }}>{attachVtResult.message || "Not found. Try full scan."}</div>}
                  </div>
                )}
                {attachVtResult?.error && <div style={{ marginTop: 8, padding: "8px 12px", background: C.redDim, borderRadius: 6, fontSize: 11, color: C.red }}>{attachVtResult.error}</div>}
              </div>
            </div>

            {/* Analyze Button */}
            <div style={{ marginTop: 18 }}>
              <button onClick={analyze} disabled={!emailText.trim() || analyzing} style={{ padding: "12px 28px", borderRadius: 8, border: "none", cursor: emailText.trim() ? "pointer" : "not-allowed", background: emailText.trim() ? C.accent : C.border, color: "#000", fontSize: 14, fontWeight: 700, fontFamily: "inherit", display: "flex", alignItems: "center", gap: 8, opacity: analyzing ? 0.7 : 1 }}>
                {analyzing ? <><Activity size={16} style={{ animation: "pulse 1s infinite" }} /> Analyzing...</> : <><Zap size={16} /> Analyze Email</>}
              </button>
            </div>
          </div>
        )}

        {/* ════════════════════════════════════════════════════════ */}
        {/* RESULTS TAB                                             */}
        {/* ════════════════════════════════════════════════════════ */}
        {activeTab === "results" && (
          <div style={{ animation: "fadeIn 0.25s ease" }}>
            {analyzing && (
              <div style={{ textAlign: "center", padding: "60px 0" }}>
                <div style={{ width: 200, height: 3, background: C.border, borderRadius: 3, margin: "0 auto 16px", overflow: "hidden" }}>
                  <div style={{ width: "40%", height: "100%", background: C.accent, borderRadius: 3, animation: "scan 1.5s infinite" }} />
                </div>
                <div style={{ fontSize: 13, color: C.textMuted }}>Running analysis layers...</div>
              </div>
            )}

            {!analyzing && !results && (
              <div style={{ textAlign: "center", padding: "60px 0", color: C.textMuted }}>
                <Mail size={40} style={{ opacity: 0.3, marginBottom: 12 }} /><div style={{ fontSize: 14 }}>Paste an email and click Analyze to see results</div>
              </div>
            )}

            {!analyzing && results && (
              <>
                {/* Combined Verdict */}
                <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "20px 24px", marginBottom: 16 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 16 }}>
                    <VerdictDisplay verdict={combined.verdict} score={combined.score || 0} />
                    <div style={{ display: "flex", gap: 12 }}>
                      {(combined.layers_active || []).map(layer => {
                        const icons = { ml: Cpu, rules: BookOpen, ai: Brain }; const labels = { ml: "ML Model", rules: "Rule Engine", ai: "AI Analysis" }; const colors = { ml: C.accent, rules: C.orange, ai: C.purple };
                        const Icon = icons[layer] || Cpu;
                        return (
                          <div key={layer} style={{ textAlign: "center", padding: "8px 14px", background: C.bg, borderRadius: 8, minWidth: 80 }}>
                            <Icon size={14} color={colors[layer]} style={{ marginBottom: 4 }} />
                            <div style={{ fontSize: 18, fontWeight: 800, fontFamily: "var(--mono)", color: colors[layer] }}>{Math.round(combined.layer_scores?.[layer] || 0)}</div>
                            <div style={{ fontSize: 9, color: C.textMuted, fontFamily: "var(--mono)" }}>{labels[layer]}</div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>

                {/* Three Layer Cards */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 16 }}>
                  <LayerCard icon={Cpu} title="ML classifier" subtitle={results.ml?.model_name || "Not trained"} color={C.accent} active={results.ml?.available} score={results.ml?.available ? Math.round(results.ml.phishing_probability) : undefined}>
                    {results.ml?.available && (
                      <div style={{ fontSize: 12 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}><span style={{ color: C.textMuted }}>Phishing prob.</span><span style={{ fontFamily: "var(--mono)", fontWeight: 600 }}>{results.ml.phishing_probability}%</span></div>
                        <div style={{ height: 4, background: C.bg, borderRadius: 2, overflow: "hidden" }}><div style={{ height: "100%", width: `${results.ml.phishing_probability}%`, background: results.ml.phishing_probability > 70 ? C.red : results.ml.phishing_probability > 40 ? C.orange : C.green, borderRadius: 2 }} /></div>
                      </div>
                    )}
                  </LayerCard>
                  <LayerCard icon={BookOpen} title="Rule engine" subtitle={`${allFindings.length} findings`} color={C.orange} active={results.rules?.available} score={results.rules?.score}>
                    {results.rules?.available && (
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        {Object.entries(results.rules.findings_by_severity || {}).filter(([, v]) => v > 0).map(([sev, count]) => (
                          <div key={sev} style={{ display: "flex", alignItems: "center", gap: 4 }}><SeverityBadge severity={sev} /><span style={{ fontSize: 12, fontFamily: "var(--mono)", color: C.textMuted }}>x{count}</span></div>
                        ))}
                      </div>
                    )}
                  </LayerCard>
                  <LayerCard icon={Brain} title="AI analysis" subtitle={aiData.ai_available ? (aiData.verdict || "analyzed") : "Not available"} color={C.purple} active={aiData.ai_available && !aiData.error} score={aiData.confidence}>
                    {aiData.ai_available && aiData.risk_summary ? (
                      <div onClick={() => setAiExpanded(!aiExpanded)} style={{ cursor: "pointer" }}>
                        <div style={{ fontSize: 12, color: C.text, lineHeight: 1.6 }}>
                          {aiExpanded ? aiData.risk_summary : aiData.risk_summary.slice(0, 150)}{!aiExpanded && aiData.risk_summary.length > 150 ? "..." : ""}
                        </div>
                        {aiData.risk_summary.length > 150 && (
                          <div style={{ fontSize: 10, color: C.purple, marginTop: 6, fontFamily: "var(--mono)", display: "flex", alignItems: "center", gap: 4 }}>
                            {aiExpanded ? <><ChevronDown size={10} /> Click to collapse</> : <><ChevronRight size={10} /> Click to expand</>}
                          </div>
                        )}
                      </div>
                    ) : !aiData.ai_available && <div style={{ fontSize: 11, color: C.textMuted, lineHeight: 1.5 }}>Install Ollama:<br /><code style={{ color: C.accent, fontSize: 10 }}>ollama pull llama3</code></div>}
                  </LayerCard>
                </div>

                {/* ── VT URL Prompt (auto-popup) ── */}
                {showVtPrompt && detectedUrls.length > 0 && !urlVtResults && (
                  <div style={{ background: C.purpleDim, border: `1px solid ${C.purple}30`, borderRadius: 10, padding: "16px 20px", marginBottom: 16, animation: "fadeIn 0.3s ease" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                      <Shield size={16} color={C.purple} />
                      <span style={{ fontSize: 13, fontWeight: 700, color: C.textBright }}>URLs detected in email</span>
                    </div>
                    <div style={{ fontSize: 12, color: C.text, marginBottom: 10 }}>
                      Found {detectedUrls.length} URL{detectedUrls.length !== 1 ? "s" : ""}. Scan on VirusTotal?
                    </div>
                    <div style={{ marginBottom: 12 }}>
                      {detectedUrls.map((url, i) => (
                        <div key={i} style={{ fontSize: 11, fontFamily: "var(--mono)", color: C.accent, padding: "3px 0", wordBreak: "break-all" }}>{url}</div>
                      ))}
                    </div>
                    <div style={{ display: "flex", gap: 8 }}>
                      <button onClick={scanDetectedUrlsVt} style={{ padding: "8px 18px", borderRadius: 6, border: "none", cursor: "pointer", background: C.purple, color: "#000", fontSize: 12, fontWeight: 700, fontFamily: "inherit", display: "flex", alignItems: "center", gap: 6 }}>
                        <Shield size={13} /> Yes, scan on VT
                      </button>
                      <button onClick={() => setShowVtPrompt(false)} style={{ padding: "8px 18px", borderRadius: 6, border: `1px solid ${C.border}`, cursor: "pointer", background: "transparent", color: C.textMuted, fontSize: 12, fontWeight: 600, fontFamily: "inherit" }}>
                        No thanks
                      </button>
                    </div>
                  </div>
                )}

                {/* VT URL scan loading */}
                {urlVtLoading && (
                  <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "16px 20px", marginBottom: 16, textAlign: "center" }}>
                    <Activity size={16} color={C.purple} style={{ animation: "pulse 1s infinite", marginBottom: 6 }} />
                    <div style={{ fontSize: 12, color: C.textMuted }}>Scanning URLs on VirusTotal... (15s per URL for rate limiting)</div>
                  </div>
                )}

                {/* VT URL scan results */}
                {urlVtResults && !urlVtResults.error && (
                  <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "18px 20px", marginBottom: 16 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                      <Shield size={15} color={C.purple} />
                      <span style={{ fontSize: 14, fontWeight: 700, color: C.textBright }}>VirusTotal URL scan results</span>
                      <span style={{ fontSize: 11, color: C.textMuted, fontFamily: "var(--mono)" }}>{urlVtResults.urls_scanned} scanned</span>
                    </div>
                    {(urlVtResults.results || []).map((r, i) => {
                      const color = r.verdict === "malicious" ? C.red : r.verdict === "suspicious" ? C.orange : C.green;
                      return (
                        <div key={i} style={{ padding: "10px 12px", background: `${color}08`, border: `1px solid ${color}25`, borderRadius: 8, marginBottom: 6 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: C.textBright, wordBreak: "break-all", flex: 1, marginRight: 10 }}>{r.scanned_url || r.url}</span>
                            <VtVerdictBadge verdict={r.verdict} />
                          </div>
                          {r.found && <div style={{ fontSize: 10, color: C.textMuted, marginTop: 4 }}>{r.malicious_count}/{r.total_engines} engines · {r.vt_link && <a href={r.vt_link} target="_blank" rel="noopener noreferrer" style={{ color: C.accent, textDecoration: "none" }}>View on VT ↗</a>}</div>}
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* ── Fallback VT button (if user dismissed prompt) ── */}
                {detectedUrls.length > 0 && !showVtPrompt && !urlVtLoading && !urlVtResults && (
                  <div style={{ marginBottom: 16 }}>
                    <button onClick={scanDetectedUrlsVt} style={{ padding: "8px 18px", borderRadius: 6, border: `1px solid ${C.purple}40`, cursor: "pointer", background: C.purpleDim, color: C.purple, fontSize: 12, fontWeight: 600, fontFamily: "inherit", display: "flex", alignItems: "center", gap: 6 }}>
                      <Shield size={13} /> Scan {detectedUrls.length} URL{detectedUrls.length !== 1 ? "s" : ""} on VirusTotal
                    </button>
                  </div>
                )}

                {/* Rescan button if already scanned */}
                {urlVtResults && detectedUrls.length > 0 && !urlVtLoading && (
                  <div style={{ marginBottom: 16 }}>
                    <button onClick={scanDetectedUrlsVt} style={{ padding: "6px 14px", borderRadius: 6, border: `1px solid ${C.border}`, cursor: "pointer", background: "transparent", color: C.textMuted, fontSize: 11, fontFamily: "inherit", display: "flex", alignItems: "center", gap: 5 }}>
                      <Shield size={11} /> Rescan URLs on VirusTotal
                    </button>
                  </div>
                )}

                {/* Detailed Findings */}
                {allFindings.length > 0 && (
                  <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "18px 20px", marginBottom: 16 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
                      <AlertTriangle size={15} color={C.orange} />
                      <span style={{ fontSize: 14, fontWeight: 700, color: C.textBright }}>Rule engine findings</span>
                      <span style={{ fontSize: 11, color: C.textMuted, fontFamily: "var(--mono)" }}>({allFindings.length})</span>
                    </div>
                    {allFindings.map((f, i) => <FindingRow key={i} finding={f} defaultOpen={i < 2} />)}
                  </div>
                )}

                {/* AI Social Engineering */}
                {aiData.ai_available && aiData.social_engineering_tactics?.length > 0 && (
                  <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "18px 20px", marginBottom: 16 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}><Brain size={15} color={C.purple} /><span style={{ fontSize: 14, fontWeight: 700, color: C.textBright }}>Social engineering tactics</span></div>
                    {aiData.social_engineering_tactics.map((t, i) => (
                      <div key={i} style={{ padding: "10px 0", borderBottom: i < aiData.social_engineering_tactics.length - 1 ? `1px solid ${C.border}` : "none" }}>
                        <div style={{ fontSize: 12, fontWeight: 600, color: C.purple, marginBottom: 4 }}>{t.tactic}</div>
                        <div style={{ fontSize: 12, color: C.text, lineHeight: 1.6 }}>{t.description}</div>
                      </div>
                    ))}
                  </div>
                )}

                {/* AI MITRE + Recommendations */}
                {aiData.ai_available && (aiData.mitre_attack?.length > 0 || aiData.recommended_actions?.length > 0) && (
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
                    {aiData.mitre_attack?.length > 0 && (
                      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "18px 20px" }}>
                        <div style={{ fontSize: 13, fontWeight: 700, color: C.textBright, marginBottom: 12 }}>MITRE ATT&CK mapping</div>
                        {aiData.mitre_attack.map((m, i) => (
                          <div key={i} style={{ padding: "8px 0", borderBottom: i < aiData.mitre_attack.length - 1 ? `1px solid ${C.border}` : "none" }}>
                            <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: C.accent, fontWeight: 600 }}>{m.technique_id}</span>
                            <span style={{ fontSize: 12, color: C.textBright, marginLeft: 8 }}>{m.technique_name}</span>
                            <div style={{ fontSize: 11, color: C.textMuted, marginTop: 2 }}>{m.relevance}</div>
                          </div>
                        ))}
                      </div>
                    )}
                    {aiData.recommended_actions?.length > 0 && (
                      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "18px 20px" }}>
                        <div style={{ fontSize: 13, fontWeight: 700, color: C.textBright, marginBottom: 12 }}>Recommended actions</div>
                        {aiData.recommended_actions.map((a, i) => (
                          <div key={i} style={{ display: "flex", gap: 8, padding: "6px 0", fontSize: 12, color: C.text, lineHeight: 1.5 }}>
                            <span style={{ color: C.green, fontWeight: 700, flexShrink: 0 }}>{i + 1}.</span>{a}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* EML info + attachments */}
                {emlInfo && (
                  <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "18px 20px", marginBottom: 16 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}><FileText size={15} color={C.accent} /><span style={{ fontSize: 14, fontWeight: 700, color: C.textBright }}>Uploaded .eml file</span><span style={{ fontSize: 11, color: C.textMuted, fontFamily: "var(--mono)" }}>{emlInfo.filename}</span></div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, marginBottom: emlInfo.attachments?.length > 0 ? 16 : 0 }}>
                      {[["From", emlInfo.from], ["To", emlInfo.to], ["Subject", emlInfo.subject], ["Date", emlInfo.date]].filter(([, v]) => v).map(([k, v]) => (
                        <div key={k} style={{ padding: "8px 10px", background: C.bg, borderRadius: 6 }}>
                          <div style={{ fontSize: 9, color: C.textMuted, fontFamily: "var(--mono)", letterSpacing: "0.06em", marginBottom: 3 }}>{k.toUpperCase()}</div>
                          <div style={{ fontSize: 11, color: C.textBright, fontFamily: "var(--mono)", wordBreak: "break-all" }}>{v}</div>
                        </div>
                      ))}
                    </div>
                    {emlInfo.attachments?.length > 0 && emlInfo.attachments.map((att, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", background: att.is_suspicious ? C.redDim : C.bg, border: `1px solid ${att.is_suspicious ? C.red + "30" : C.border}`, borderRadius: 6, marginBottom: 6 }}>
                        <FileText size={14} color={att.is_suspicious ? C.red : C.textMuted} />
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: att.is_suspicious ? C.red : C.textBright }}>{att.filename}</div>
                          <div style={{ fontSize: 10, color: C.textMuted, fontFamily: "var(--mono)" }}>{att.content_type} · {(att.size / 1024).toFixed(1)} KB</div>
                          {att.is_suspicious && <div style={{ fontSize: 11, color: C.red, marginTop: 3 }}>{att.risk_note}</div>}
                        </div>
                        {att.is_suspicious ? <SeverityBadge severity="critical" /> : <span style={{ fontSize: 10, color: C.green, fontFamily: "var(--mono)" }}>SAFE</span>}
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* ════════════════════════════════════════════════════════ */}
        {/* VIRUSTOTAL TAB                                          */}
        {/* ════════════════════════════════════════════════════════ */}
        {activeTab === "virustotal" && (
          <div style={{ animation: "fadeIn 0.2s ease" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {/* URL Scanner */}
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "20px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}><Link2 size={16} color={C.accent} /><span style={{ fontSize: 14, fontWeight: 700, color: C.textBright }}>URL scanner</span></div>
                <div style={{ fontSize: 11, color: C.textMuted, marginBottom: 12, lineHeight: 1.5 }}>Paste URLs to check against VirusTotal. One URL per line.</div>
                <textarea value={vtTabUrls} onChange={e => setVtTabUrls(e.target.value)} placeholder={"https://suspicious-link.xyz/login\nhttps://another-url.com/verify"}
                  style={{ width: "100%", minHeight: 100, padding: "12px", borderRadius: 8, border: `1px solid ${C.border}`, background: C.bg, color: C.textBright, fontSize: 12, fontFamily: "var(--mono)", lineHeight: 1.6, resize: "vertical" }} />
                <button onClick={scanVtTabUrls} disabled={!vtTabUrls.trim() || vtTabUrlLoading} style={{ marginTop: 12, padding: "10px 20px", borderRadius: 8, border: "none", cursor: vtTabUrls.trim() ? "pointer" : "not-allowed", background: vtTabUrls.trim() ? C.accent : C.border, color: "#000", fontSize: 13, fontWeight: 700, fontFamily: "inherit", display: "flex", alignItems: "center", gap: 8, opacity: vtTabUrlLoading ? 0.7 : 1 }}>
                  {vtTabUrlLoading ? <><Activity size={14} style={{ animation: "pulse 1s infinite" }} /> Scanning...</> : <><Shield size={14} /> Scan URLs</>}
                </button>
                {vtTabUrlResults && !vtTabUrlResults.error && (
                  <div style={{ marginTop: 16 }}>
                    {(vtTabUrlResults.results || []).map((r, i) => {
                      const color = r.verdict === "malicious" ? C.red : r.verdict === "suspicious" ? C.orange : C.green;
                      return (
                        <div key={i} style={{ padding: "10px 12px", background: `${color}08`, border: `1px solid ${color}25`, borderRadius: 8, marginBottom: 6 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: C.textBright, wordBreak: "break-all", flex: 1, marginRight: 10 }}>{r.scanned_url || r.url}</span>
                            <VtVerdictBadge verdict={r.verdict} />
                          </div>
                          {r.found && <div style={{ fontSize: 10, color: C.textMuted, marginTop: 4 }}>{r.malicious_count}/{r.total_engines} engines {r.vt_link && <a href={r.vt_link} target="_blank" rel="noopener noreferrer" style={{ color: C.accent, textDecoration: "none" }}>View on VT ↗</a>}</div>}
                        </div>
                      );
                    })}
                  </div>
                )}
                {vtTabUrlResults?.error && <div style={{ marginTop: 12, padding: "10px 14px", background: C.redDim, border: `1px solid ${C.red}30`, borderRadius: 8, fontSize: 12, color: C.red }}>{vtTabUrlResults.error}</div>}
              </div>

              {/* File Scanner */}
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "20px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}><FileText size={16} color={C.purple} /><span style={{ fontSize: 14, fontWeight: 700, color: C.textBright }}>File scanner</span></div>
                <div style={{ fontSize: 11, color: C.textMuted, marginBottom: 12, lineHeight: 1.5 }}>Upload a suspicious file. Computes SHA-256 and checks VirusTotal.</div>
                <div style={{ display: "flex", gap: 4, marginBottom: 14, background: C.bg, borderRadius: 6, padding: 3, width: "fit-content" }}>
                  {[{ id: "hash", label: "Hash lookup (fast)" }, { id: "full", label: "Full scan (thorough)" }].map(m => (
                    <button key={m.id} onClick={() => setVtTabFileMode(m.id)} style={{ padding: "6px 14px", borderRadius: 5, border: "none", cursor: "pointer", fontSize: 11, fontWeight: 600, fontFamily: "inherit", background: vtTabFileMode === m.id ? C.purple : "transparent", color: vtTabFileMode === m.id ? "#000" : C.textMuted }}>{m.label}</button>
                  ))}
                </div>
                <div onClick={() => vtTabFileRef.current?.click()} style={{ border: `2px dashed ${C.border}`, borderRadius: 8, padding: "28px 20px", textAlign: "center", cursor: "pointer" }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = C.purple} onMouseLeave={e => e.currentTarget.style.borderColor = C.border}>
                  <input ref={vtTabFileRef} type="file" style={{ display: "none" }} onChange={e => { if (e.target.files[0]) scanVtTabFile(e.target.files[0]); e.target.value = ""; }} />
                  <Upload size={22} color={C.textMuted} style={{ marginBottom: 6 }} />
                  <div style={{ fontSize: 12, fontWeight: 600, color: C.textBright }}>{vtTabFileLoading ? "Scanning..." : "Click to upload a file"}</div>
                  <div style={{ fontSize: 10, color: C.textMuted }}>{vtTabFileMode === "hash" ? "SHA-256 hash check — instant" : "Full upload — takes 1-2 minutes"}</div>
                </div>
                {vtTabFileResult && !vtTabFileResult.error && (
                  <div style={{ marginTop: 16, padding: "14px", background: C.bg, borderRadius: 8, border: `1px solid ${C.border}` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                      <span style={{ fontSize: 13, fontWeight: 700, color: C.textBright }}>{vtTabFileResult.filename || "File"}</span>
                      <VtVerdictBadge verdict={vtTabFileResult.verdict} />
                    </div>
                    {vtTabFileResult.found ? (
                      <>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 10 }}>
                          {[["MALICIOUS", vtTabFileResult.malicious_count, vtTabFileResult.malicious_count > 0 ? C.red : C.green], ["ENGINES", vtTabFileResult.total_engines, C.textBright], ["DETECTION", `${vtTabFileResult.detection_rate}%`, C.accent]].map(([label, val, color]) => (
                            <div key={label} style={{ padding: "8px", background: C.surface, borderRadius: 6, textAlign: "center" }}>
                              <div style={{ fontSize: 20, fontWeight: 800, fontFamily: "var(--mono)", color }}>{val}</div>
                              <div style={{ fontSize: 9, color: C.textMuted, fontFamily: "var(--mono)" }}>{label}</div>
                            </div>
                          ))}
                        </div>
                        {vtTabFileResult.hashes?.sha256 && <div style={{ fontSize: 10, fontFamily: "var(--mono)", color: C.textMuted, wordBreak: "break-all", marginBottom: 4 }}>SHA-256: {vtTabFileResult.hashes.sha256}</div>}
                        {vtTabFileResult.vt_link && <a href={vtTabFileResult.vt_link} target="_blank" rel="noopener noreferrer" style={{ display: "inline-flex", alignItems: "center", gap: 4, color: C.accent, fontSize: 11, textDecoration: "none", marginTop: 8 }}>View on VirusTotal <ExternalLink size={11} /></a>}
                      </>
                    ) : <div style={{ fontSize: 12, color: C.orange }}>{vtTabFileResult.message || "Not found. Try full scan."}</div>}
                  </div>
                )}
                {vtTabFileResult?.error && <div style={{ marginTop: 12, padding: "10px 14px", background: C.redDim, border: `1px solid ${C.red}30`, borderRadius: 8, fontSize: 12, color: C.red }}>{vtTabFileResult.error}</div>}
              </div>
            </div>

            <div style={{ marginTop: 16, padding: "10px 16px", background: C.surface, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div style={{ fontSize: 11, color: C.textMuted }}>VirusTotal free tier: 4 requests/minute, 500/day.</div>
              <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 10, fontFamily: "var(--mono)", color: aiStatus?.vt_available ? C.green : C.red }}>
                <span style={{ width: 5, height: 5, borderRadius: "50%", background: aiStatus?.vt_available ? C.green : C.red }} />
                {aiStatus?.vt_available ? "VT CONNECTED" : "VT NOT CONFIGURED"}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Disclaimer */}
      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "16px 24px 32px" }}>
        <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 16 }}>
          <div style={{ fontSize: 10, color: C.textMuted, lineHeight: 1.7, fontFamily: "var(--mono)" }}>
            <span style={{ fontWeight: 600, color: C.textMuted }}>DISCLAIMER:</span> DetectPhish is a cybersecurity research and educational tool built as a portfolio project. It is not a substitute for professional email security solutions, enterprise-grade threat detection systems, or expert security analysis. Detection results are probabilistic and may contain false positives or false negatives. Do not rely solely on this tool for security decisions. VirusTotal integration uses their public API under their terms of service. AI analysis runs locally via Ollama — no email content is sent to external AI services unless explicitly configured. Use responsibly and in compliance with applicable laws and regulations.
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Client-Side Demo Analysis (when API is offline) ──

function generateDemoResults(text, subject) {
  const lower = text.toLowerCase();
  const urgencyWords = ["urgent", "immediately", "verify", "suspend", "confirm", "expire", "action required", "click here", "within 24 hours", "permanently"];
  const urgencyCount = urgencyWords.filter(w => lower.includes(w)).length;
  const threatWords = ["legal action", "close your account", "permanently", "forced to"];
  const threatCount = threatWords.filter(w => lower.includes(w)).length;
  const financialWords = ["wire transfer", "bank", "payment", "credit card", "gift card", "bitcoin"];
  const financialCount = financialWords.filter(w => lower.includes(w)).length;
  const hasGenericGreeting = /dear (customer|user|member|valued)/i.test(lower);
  const hasSuspiciousTLD = /https?:\/\/[^\s]*\.(xyz|top|tk|ml|ga|click)/.test(lower);

  let ruleScore = 0; const findings = [];
  if (urgencyCount >= 3) { ruleScore += 25; findings.push({ rule_id: "CON-001", name: "Heavy urgency language", severity: "high", description: `${urgencyCount} urgency tactics detected.`, evidence: `${urgencyCount} patterns` }); }
  else if (urgencyCount >= 1) { ruleScore += 10; findings.push({ rule_id: "CON-002", name: "Urgency language detected", severity: "medium", description: "Urgency indicators found.", evidence: `${urgencyCount} patterns` }); }
  if (threatCount > 0) { ruleScore += 20; findings.push({ rule_id: "CON-009", name: "Threatening consequences", severity: "high", description: "Threats used to pressure recipient.", evidence: `${threatCount} patterns` }); }
  if (financialCount > 0) { ruleScore += 25; findings.push({ rule_id: "CON-010", name: "Money transfer request", severity: "critical", description: "Financial information requested.", evidence: `${financialCount} patterns` }); }
  if (hasGenericGreeting) { ruleScore += 5; findings.push({ rule_id: "CON-004", name: "Generic greeting", severity: "low", description: "Uses generic greeting instead of name." }); }
  if (hasSuspiciousTLD) { ruleScore += 15; findings.push({ rule_id: "URL-002", name: "Suspicious TLD", severity: "medium", description: "URL uses TLD associated with phishing." }); }
  if (/paypa1|micr0soft|g00gle|arnazon/.test(lower)) { ruleScore += 30; findings.push({ rule_id: "URL-004", name: "Homoglyph detected", severity: "critical", description: "Domain uses lookalike characters." }); }

  ruleScore = Math.min(ruleScore, 100);
  const mlScore = Math.min(urgencyCount * 15 + threatCount * 20 + financialCount * 20 + (hasSuspiciousTLD ? 15 : 0) + (hasGenericGreeting ? 5 : 0), 100);
  const combinedScore = Math.round(mlScore * 0.5 + ruleScore * 0.5);

  return {
    analyzed_at: new Date().toISOString(),
    ml: { available: true, phishing_probability: mlScore, legitimate_probability: 100 - mlScore, verdict: mlScore >= 70 ? "phishing" : mlScore >= 40 ? "suspicious" : "legitimate", model_name: "demo_mode" },
    rules: { available: true, score: ruleScore, verdict: ruleScore >= 60 ? "phishing" : ruleScore >= 30 ? "suspicious" : "legitimate", total_findings: findings.length, findings_by_severity: { critical: findings.filter(f => f.severity === "critical").length, high: findings.filter(f => f.severity === "high").length, medium: findings.filter(f => f.severity === "medium").length, low: findings.filter(f => f.severity === "low").length }, all_findings: findings },
    ai: { ai_available: false, error: "Demo mode — install Ollama for AI analysis" },
    combined: { score: combinedScore, verdict: combinedScore >= 70 ? "phishing" : combinedScore >= 40 ? "suspicious" : "legitimate", layer_scores: { ml: mlScore, rules: ruleScore }, layer_weights: { ml: 0.55, rules: 0.45 }, layers_active: ["ml", "rules"] },
  };
}
