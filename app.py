import json, os, re, secrets, tempfile
from pathlib import Path
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

APP = "BeforePush"
MODEL = "gemma-4-26b-a4b-it"

HOOK_SCRIPT = r"""#!/bin/sh
# BeforePush local pre-commit firewall. Scans staged additions only; never prints matched secret text.
PATTERN='(gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{30,}|(AKIA|ASIA)[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_live_[A-Za-z0-9]{16,})'
if git diff --cached --no-ext-diff --unified=0 | grep '^+' | grep -v '^+++' | grep -Eiq "$PATTERN"; then
  echo "BeforePush blocked this commit: a supported secret pattern is staged. Remove or rotate the credential, then try again."
  exit 1
fi
exit 0
"""
MAX_BYTES = 1_000_000
SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", "dist", "build"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".exe", ".dll", ".pyc", ".sqlite"}
RULES = [
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Critical", "A private key can grant access to accounts or servers.", "Revoke or rotate it. Store the replacement in a secret manager."),
    ("GitHub token", re.compile(r"(?P<secret>\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b)"), "Critical", "A repository token may allow access to code and releases.", "Revoke it in GitHub, create a least-privilege replacement, and load it from an environment variable."),
    ("Google API key", re.compile(r"(?P<secret>\bAIza[0-9A-Za-z_-]{30,}\b)"), "High", "An exposed Google API key may be abused within its attached permissions.", "Restrict or rotate it in Google Cloud, then use an environment variable."),
    ("AWS access key ID", re.compile(r"(?P<secret>\b(?:AKIA|ASIA)[0-9A-Z]{16}\b)"), "Critical", "An AWS access key may expose cloud resources.", "Disable and rotate it in IAM; prefer a role or short-lived credentials."),
    ("Slack token", re.compile(r"(?P<secret>\bxox[baprs]-[A-Za-z0-9-]{20,}\b)"), "High", "A Slack token may provide access to messages or workspace actions.", "Revoke it in Slack and load a replacement from a secret manager."),
    ("Stripe live secret key", re.compile(r"(?P<secret>\bsk_live_[A-Za-z0-9]{16,}\b)"), "Critical", "A live payment secret can enable unauthorized payment operations.", "Roll the key in Stripe and keep the replacement on a trusted server."),
    ("Credential assignment", re.compile(r"""(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret|token)\s*[:=]\s*["']?(?P<secret>[^\s'"",;]{8,})"""), "Medium", "A credential-like setting may contain a hard-coded secret.", "Move it to an environment variable and add local secret files to .gitignore."),
]

def mask(value):
    return f"[REDACTED · {len(value)} characters]"

def placeholder(value):
    low = value.lower()
    return any(word in low for word in ("your_", "example", "placeholder", "redacted", "changeme")) or set(value) <= set("xX01*-")

def redact(line):
    for _, pattern, *_ in RULES:
        line = pattern.sub(lambda m: mask(m.groupdict().get("secret") or m.group(0)), line)
    return line.strip()[:400]

def scan_file(path, root):
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_BYTES or b"\0" in raw[:4096]:
            return []
        content = raw.decode("utf-8", errors="replace")
        relative = str(path.relative_to(root))
    except (OSError, ValueError):
        return []
    findings = []
    for line_no, line in enumerate(content.splitlines(), 1):
        seen = set()
        for name, pattern, severity, why, fix in RULES:
            for match in pattern.finditer(line):
                value = match.groupdict().get("secret") or match.group(0)
                if len(value) < 8 or placeholder(value) or value in seen:
                    continue
                seen.add(value)
                findings.append({"file": relative, "line": line_no, "rule": name, "severity": severity, "why": why, "fix": fix, "redacted_line": redact(line)})
    return findings

def scan_folder(root):
    findings, count = [], 0
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for name in files:
            path = Path(current) / name
            if path.is_symlink() or path.suffix.lower() in SKIP_EXT:
                continue
            count += 1
            findings.extend(scan_file(path, root))
    return findings, count

def make_demo():
    root = Path(tempfile.gettempdir()) / "commitsafe-safe-demo"
    root.mkdir(parents=True, exist_ok=True)
    fake = "ghp_" + "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789") for _ in range(32))
    (root / "settings.py").write_text("# Safe demo only: generated fake token, not a credential.\n" + f'GITHUB_TOKEN = "{fake}"\nAPI_BASE_URL = "https://api.example.test/v1"\n', encoding="utf-8")
    return root

def gemma_fix(item):
    if not (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")):
        raise RuntimeError("GEMINI_API_KEY is missing. Add it to Windows user environment variables and restart the app.")
    from google import genai
    prompt = ("You are BeforePush, a developer security coach. A local scanner found a possible secret; its raw value was removed. "
              "Never ask for the real value or claim it is active. In under 100 words, explain the risk, safest immediate action, and practical code/config fix.\n"
              f"Rule: {item['rule']}\nSeverity: {item['severity']}\nFile type: {Path(item['file']).suffix or 'unknown'}\nSanitized line: {item['redacted_line']}")
    # Keep the client alive for the full request. An inline temporary client can
    # close before its HTTP request is sent ("client has been closed").
    with genai.Client() as client:
        response = client.models.generate_content(model=MODEL, contents=prompt)
    if not (response.text or "").strip():
        raise RuntimeError("Gemma returned an empty answer.")
    return response.text.strip()

def safe_report(findings, scanned, project):
    items = [{"file": x["file"], "line": x["line"], "rule": x["rule"], "severity": x["severity"], "secret": "[REDACTED]", "redacted_line": x["redacted_line"], "recommended_fix": x["fix"]} for x in findings]
    return json.dumps({"product": APP, "project": project, "files_scanned": scanned, "finding_count": len(items), "findings": items}, indent=2).encode()

st.set_page_config(page_title=f"{APP} | Commit Guard", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
html,body,[class*="css"]{font-family:Manrope,sans-serif}
[data-testid="stAppViewContainer"]{background:radial-gradient(ellipse at 10% 0%,#122b38,#09131c 42%,#070d14);color:#edf5f7}
[data-testid="stHeader"]{background:transparent}.block-container{max-width:1240px;padding-top:2rem}
h1,h2,h3{color:#f1f8fa!important;letter-spacing:-.035em}p,label{color:#bbcad0}
.hero{border:1px solid #284c50;border-radius:24px;padding:30px 34px;background:linear-gradient(120deg,#11303a,#0e1b27);box-shadow:0 24px 80px #0004;margin-bottom:22px}
.eyebrow,.smallcap{font:500 11px 'DM Mono',monospace;letter-spacing:.13em;color:#79e3c5;text-transform:uppercase}
.hero h1{font-size:52px;margin:8px 0}.hero p{font-size:16px;line-height:1.6;max-width:780px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:18px}.chip{border:1px solid #ffffff25;border-radius:99px;padding:7px 11px;font:11px 'DM Mono',monospace;color:#d3e2e5}
.panel{border:1px solid #ffffff20;border-radius:18px;background:#0f1c27c9;padding:20px}
.stButton>button{border-radius:11px;background:linear-gradient(135deg,#7ae3c5,#51c9b4);color:#07151a!important;font-weight:800;min-height:44px;border:0}.stButton>button:hover{color:#07151a!important;filter:brightness(1.04)}.stDownloadButton>button{color:#07151a!important}
[data-testid="stMetric"]{background:#0f1c27;border:1px solid #ffffff20;border-radius:15px;padding:15px}
[data-testid="stMetricLabel"] p{font:11px 'DM Mono',monospace;text-transform:uppercase;color:#94aeb5!important}
[data-testid="stMetricValue"]{color:#f1f8fa}[data-testid="stExpander"]{border:1px solid #ffffff22;border-radius:14px;background:#0d1923}
footer{visibility:hidden}
</style>
""", unsafe_allow_html=True)

for key, default in {"findings": [], "scanned": 0, "root": "", "complete": False, "blocked": False}.items():
    if key not in st.session_state:
        st.session_state[key] = default

st.markdown(f"""<section class="hero"><div class="eyebrow">LOCAL-FIRST DEVELOPER SECURITY</div>
<h1>{APP}<span style="color:#79e3c5">.</span></h1>
<p>Catch secrets before they ship. Scan a project on your machine, find the risky line, and get a safe fix before it reaches a public repository.</p>
<div class="chips"><span class="chip">DETECTION STAYS LOCAL</span><span class="chip">REDACTED REPORTS</span><span class="chip">OPTIONAL GEMMA 4 FIX COACH</span></div></section>""", unsafe_allow_html=True)

left, right = st.columns([1.2, .8], gap="large")
with left:
    st.markdown('<div class="smallcap">01 / Choose what to inspect</div>', unsafe_allow_html=True)
    folder = st.text_input("Project folder path", value=st.session_state.root, placeholder=r"Example: C:\Users\you\Documents\my-project", help="Scanning runs locally. Git metadata, virtual environments and common build folders are skipped.", label_visibility="collapsed")
    c1, c2 = st.columns(2)
    with c1:
        scan_clicked = st.button("🔎  Scan project", use_container_width=True, type="primary")
    with c2:
        demo_clicked = st.button("✨  Load safe demo", use_container_width=True)
    if demo_clicked:
        root = make_demo()
        st.session_state.root = str(root)
        st.session_state.findings, st.session_state.scanned = scan_folder(root)
        st.session_state.complete, st.session_state.blocked = True, False
        st.rerun()
    if scan_clicked:
        root = Path(folder.strip().strip('"')).expanduser()
        if not folder.strip():
            st.error("Enter a folder path, or use the safe demo.")
        elif not root.is_dir():
            st.error("Folder not found. Check the path and try again.")
        else:
            root = root.resolve()
            with st.spinner("Scanning files locally…"):
                st.session_state.findings, st.session_state.scanned = scan_folder(root)
            st.session_state.root = str(root)
            st.session_state.complete, st.session_state.blocked = True, False
            st.rerun()
with right:
    st.markdown("""<div class="panel"><div class="smallcap">Privacy boundary</div>
    <p style="line-height:1.65;margin-top:10px">Detection runs locally. If requested, Gemma receives the rule, file type and a redacted line—never the detected value.</p></div>""", unsafe_allow_html=True)

if st.session_state.complete:
    findings = st.session_state.findings
    critical = sum(x["severity"] == "Critical" for x in findings)
    high = sum(x["severity"] == "High" for x in findings)
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="smallcap">02 / Scan results</div>', unsafe_allow_html=True)
    cols = st.columns(4)
    cols[0].metric("Files inspected", st.session_state.scanned)
    cols[1].metric("Findings", len(findings))
    cols[2].metric("Critical", critical)
    cols[3].metric("High", high)
    if findings:
        st.warning(f"{len(findings)} possible secret(s) found. Values are hidden here and in the report.")
        for i, item in enumerate(findings):
            with st.expander(f"{item['severity'].upper()} · {item['rule']} · {item['file']}:{item['line']}", expanded=(i == 0)):
                st.markdown(f"**Why it matters:** {item['why']}")
                st.markdown(f"**Suggested first step:** {item['fix']}")
                st.code(item["redacted_line"], language="text")
                if st.button("✨  Ask Gemma 4 for a tailored fix", key=f"gemma-{i}"):
                    with st.spinner("Sending only redacted context to Gemma 4…"):
                        try:
                            st.session_state[f"answer-{i}"] = gemma_fix(item)
                            st.session_state[f"error-{i}"] = ""
                        except Exception as exc:
                            st.session_state[f"error-{i}"] = str(exc)
                    st.rerun()
                if st.session_state.get(f"answer-{i}"):
                    st.markdown("**Gemma 4 fix coach**")
                    st.markdown(st.session_state[f"answer-{i}"])
                elif st.session_state.get(f"error-{i}"):
                    st.info("Gemma is temporarily unavailable. The local finding and safe fix above are still available; click the Gemma button again in a moment.")
        st.markdown("<br>", unsafe_allow_html=True)
        gate, report = st.columns(2)
        with gate:
            if st.button("⛔  Simulate commit gate", use_container_width=True):
                st.session_state.blocked = True
            st.download_button("⬇️  Download real Git pre-commit hook", data=HOOK_SCRIPT, file_name="pre-commit", mime="text/x-sh", use_container_width=True, help="Install this file in your repository's .git/hooks folder to block supported secrets before commit.")
        with report:
            data = safe_report(findings, st.session_state.scanned, Path(st.session_state.root).name)
            st.download_button("⬇️  Download redacted report", data=data, file_name="beforepush-report.json", mime="application/json", use_container_width=True)
        if st.session_state.blocked:
            st.error("COMMIT BLOCKED · Fix or remove the finding, then scan again before pushing.")
        st.caption("The button demonstrates the commit gate. For real Git protection, download the hook and place it at .git/hooks/pre-commit; it checks staged additions locally and does not print secret values.")
    else:
        st.success("No supported secret patterns found in the scanned files.")
        st.markdown("**Looks clear.** Keep credentials in environment variables or a secret manager.")

st.markdown("<br>", unsafe_allow_html=True)
st.caption("BeforePush is a prototype. Pattern scanning may miss secrets or flag false positives; rotate credentials that may have been exposed.")

