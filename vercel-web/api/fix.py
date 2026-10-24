import json, os, re
from http.server import BaseHTTPRequestHandler
from google import genai
MODEL = "gemma-4-26b-a4b-it"
SECRET_RE = re.compile(r"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{30,}|(?:AKIA|ASIA)[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_live_[A-Za-z0-9]{16,})")
class handler(BaseHTTPRequestHandler):
    def send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size <= 0 or size > 12000: return self.send_json(400, {"error":"Invalid request size."})
            data = json.loads(self.rfile.read(size))
            rule, severity = str(data.get("rule",""))[:100], str(data.get("severity",""))[:30]
            file_type, line = str(data.get("file_type",""))[:20], str(data.get("redacted_line",""))[:400]
            if not all((rule,severity,line)): return self.send_json(400, {"error":"Finding details are incomplete."})
            if SECRET_RE.search(line): return self.send_json(400, {"error":"Raw credential detected in request; redact it before asking Gemma."})
            if not (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")):
                return self.send_json(503, {"error":"Add GEMINI_API_KEY in Vercel project settings."})
            prompt=("You are BeforePush, a developer security coach. The raw secret was removed before this request. "
                    "Never ask for the real value or claim it is active. In under 100 words, explain the risk, immediate "
                    "action, and practical code/config fix in beginner-friendly language.\n"
                    f"Rule: {rule}\nSeverity: {severity}\nFile type: {file_type}\nSanitized line: {line}")
            with genai.Client() as client:
                response=client.models.generate_content(model=MODEL, contents=prompt)
            answer=(response.text or "").strip()
            if not answer: return self.send_json(502, {"error":"Gemma returned an empty answer. Retry."})
            return self.send_json(200, {"answer":answer})
        except Exception:
            return self.send_json(502, {"error":"Gemma is temporarily unavailable. Retry in a moment."})
    def do_GET(self):
        return self.send_json(405, {"error":"Use POST for Gemma fix requests."})
