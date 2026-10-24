# BeforePush Vercel version

Separate Vercel web app; the original Streamlit app remains in the parent folder.

## Privacy and Gemma 4
Files are scanned in the visitor's browser and are not uploaded. When requested, Gemma receives only the rule, severity, file extension, and redacted line. The API key stays in Vercel's server environment. A Node.js server function calls the Gemma 4 API; it validates the redacted line, retries temporary 5xx/429 errors once, and never returns the key to the browser. Model: gemma-4-26b-a4b-it.

## Deploy
1. Push the parent beforepush folder to GitHub. The existing .gitignore excludes .env; never commit a key.
2. Import the repository in Vercel and set Root Directory to vercel-web.
3. Add GEMINI_API_KEY in Vercel Project Settings > Environment Variables for Preview and Production.
4. Deploy; open the URL, choose Load safe demo, scan, and ask Gemma for a tailored fix.

Google's API may occasionally return a server error. Local detection and safe advice remain available and the page offers a retry.

## Standout feature
The downloadable Git pre-commit hook checks staged additions locally and blocks supported token patterns before commit. It does not send staged code to a service or print matched secret text.

## Install the Git hook
Download pre-commit from the app, place it in your repository at .git/hooks/pre-commit, and run chmod +x .git/hooks/pre-commit from Git Bash. The hook checks staged additions locally and blocks supported token patterns before commit.
