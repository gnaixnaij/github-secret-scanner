# GitHub Secret Scanner

Find leaked secrets in any public GitHub repo. Paste a repo URL → scan for API keys, tokens, passwords, private keys, and connection strings.

👉 **Live site coming soon**

## Features

- Scans 30+ secret types: AWS keys, GitHub tokens, Slack tokens, private keys, JWT, Google API keys, Stripe keys, database URIs, and more
- Smart file filtering (skips binaries, node_modules, images)
- Severity classification (high/medium/low)
- Reveals masked snippets of found secrets

## Quick start

```bash
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

## Deploy

Deploy on Render (free):
1. Connect repo
2. Start command: `gunicorn app:app`
3. Done
