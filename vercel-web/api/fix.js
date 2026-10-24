const MODEL = "gemma-4-26b-a4b-it";
const SECRET_RE = /(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{30,}|(?:AKIA|ASIA)[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_live_[A-Za-z0-9]{16,})/;

const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

function cleanAnswer(value) {
  let text = String(value || "").replace(/\r/g, "").trim();
  if (/input data:|one immediate action|one practical code|no introduction|do not include an introduction|sanitized line:/i.test(text)) return "";
  text = text.replace(/^\s*Draft\s*\d+\s*:\s*/i, "").replace(/\*{1,2}/g, "");
  return text.split(/\s+/).slice(0, 90).join(" ");
}

export default async function handler(request, response) {
  if (request.method !== "POST") {
    return response.status(405).json({ error: "Use POST for Gemma fix requests." });
  }

  const data = typeof request.body === "string" ? JSON.parse(request.body) : (request.body || {});
  const rule = String(data.rule || "").slice(0, 100);
  const severity = String(data.severity || "").slice(0, 30);
  const fileType = String(data.file_type || "").slice(0, 20);
  const redactedLine = String(data.redacted_line || "").slice(0, 400);

  if (!rule || !severity || !redactedLine) {
    return response.status(400).json({ error: "Finding details are incomplete." });
  }
  if (SECRET_RE.test(redactedLine)) {
    return response.status(400).json({ error: "A raw credential was detected in the request. Redact it before asking Gemma." });
  }

  const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
  if (!apiKey) {
    return response.status(503).json({ error: "Add GEMINI_API_KEY in Vercel project settings." });
  }

  const prompt = [
    "You are BeforePush, a developer security coach. A local scanner found a possible secret; its raw value was removed before this request.",
    "Give a direct, beginner-friendly remediation. Explain the risk, one immediate action, and one safe code or configuration fix. Keep it under 70 words. Do not repeat the input or ask for the secret value.",
    "Rule: " + rule,
    "Severity: " + severity,
    "File type: " + fileType,
    "Sanitized line: " + redactedLine
  ].join("\n");

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const upstream = await fetch(
        "https://generativelanguage.googleapis.com/v1beta/models/" + MODEL + ":generateContent",
        {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { maxOutputTokens: 180, temperature: 0.2 }
          }),
          signal: AbortSignal.timeout(25000)
        }
      );

      if (upstream.ok) {
        const result = await upstream.json();
        const answer = cleanAnswer((result.candidates || []).flatMap(c => c.content?.parts || []).map(p => p.text || "").join(""));
        if (answer) return response.status(200).json({ answer });
        return response.status(502).json({ error: "Gemma returned an empty answer. Retry." });
      }

      if ((upstream.status >= 500 || upstream.status === 429) && attempt === 0) {
        await wait(900);
        continue;
      }
      return response.status(502).json({
        error: upstream.status >= 500 || upstream.status === 429
          ? "Gemma is temporarily unavailable. Retry in a moment."
          : "Gemma API rejected the request. Check the Vercel API key and model access."
      });
    } catch {
      if (attempt === 0) {
        await wait(900);
        continue;
      }
      return response.status(502).json({ error: "Gemma is temporarily unavailable. Retry in a moment." });
    }
  }
  return response.status(502).json({ error: "Gemma is temporarily unavailable. Retry in a moment." });
}
