# BeforePush

**Catch secrets before they ship.** BeforePush scans project files locally, reports possible credentials with severity and file/line locations, redacts values in reports, and offers an optional Gemma 4 fix coach.

## Run on Windows

PowerShell in this folder:

    py -m pip install -r requirements.txt
    py -m streamlit run app.py

Or double-click `run.bat` after installing requirements.

## Demo

Click **Load safe demo** for a randomly generated fake token, or enter a local project folder and click **Scan project**. Review the redacted finding, optionally ask Gemma for a tailored fix, download a real local pre-commit firewall hook, and download the redacted JSON report.

The optional hosted Gemma call receives only the rule, severity, file type, and redacted line. The raw detected value is not sent. For Gemma, copy `.env.example` to `.env` in this folder and put your key after `GEMINI_API_KEY=`. The app loads `.env` locally; `.env` is ignored by Git. Never share or commit the real key. The on-screen gate is a demo; the downloadable hook can be installed in .git/hooks/pre-commit to block supported tokens in staged additions before commit. Pattern scanning can miss secrets or flag false positives.

## Pitch

“A developer is about to commit a credential. BeforePush finds it locally, hides the value, explains the risk, and blocks the demo commit until the code is fixed. Gemma 4 turns the sanitized finding into beginner-friendly remediation.”


## Install the Git hook
Download the pre-commit file from the app, place it in your repository at .git/hooks/pre-commit, then use Git Bash to run: chmod +x .git/hooks/pre-commit. It blocks supported tokens in staged additions and prints only a generic message.
